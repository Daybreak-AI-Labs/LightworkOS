"""Swarms that add and update features in vaulted code -- and never ship alone.

``propose`` runs a goal against a private working copy on a new branch, labelled
``code:<repo>`` and enforced at the repository's protection mode so the code
cannot leave through an external tool. It then:

1. commits the working copy's files host-side and pins that commit in a bundle;
2. runs the repository's tests through the sandbox on a FRESH copy of the
   pinned commit, in tiers: the quick tier (``quick_test_command``, else the
   full suite) after each author round, then, once it passes, the full suite
   (``test_command``) and the gate (``gate_command``) on the same commit.
   A failure in any of them goes back to the author as a follow-up goal, and
   the loop repeats for up to ``[codebase] repair_rounds`` rounds;
3. runs the independent checkers, when supplied (``[codebase] checkers``, one
   by default): each a separate goal with a fresh context and its own throwaway
   copy of the pinned commit, which tries to break the change and reports
   findings without seeing another checker's. A finding may carry a ``repro``
   command (and probe files); Lightwork re-runs it on a fresh copy of the
   pinned commit, so "confirmed" is Lightwork's word, not the checker's.
   Blockers from any checker go back to the author, confirmed repros are
   re-run on the repaired commit, then the checkers look again, for up to
   ``[codebase] check_rounds`` looks;
4. runs the full suite and the gate again on the final commit when it
   changed since they last ran, then the heavy tier (``heavy_test_command``,
   tests that need services) in ``[codebase] checker_image`` only;
5. runs the independent diff reviewer, when one is supplied;
6. seals the proposal (diff, tests, rounds, findings, review, branch bundle) and
   parks a ``codebase_merge`` approval in the real approvals queue.

Every round, the author's and the checker's, is charged to one budget, checked
before the round starts and before each test tier runs; when it runs out the
loop stops and the card says so.

Nothing reaches the vault's default branch or any remote until a person
approves: ``merge`` needs the approval, ``push`` needs it too. A denied approval
leaves the vault untouched.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from ..budget import BudgetExceeded
from ..channel_approvals import CODE_PROTECTED_PROVENANCE
from ..file_lock import atomic_write_bytes, cross_process_lock
from . import vault
from .vault import VaultError, _git

MAX_DIFF_CHARS = 200_000
MAX_TEST_OUTPUT_CHARS = 20_000
MAX_REPAIR_OUTPUT_CHARS = 6_000
MAX_FINDINGS = 20
MAX_PROTECTED_LISTED = 200
# A protected proposal's approval: two distinct people, neither the person who
# started the feature run (channel_approvals.ALWAYS_SEPARATE_PROVENANCES).
PROTECTED_PROVENANCE = CODE_PROTECTED_PROVENANCE
PROTECTED_APPROVALS = 2
MAX_REPRO_CHARS = 2_000
MAX_PROBE_FILES = 3
MAX_PROBE_BYTES = 20 * 1024
REPRO_TIMEOUT = 600
# The checker image's entrypoint exits with this code when it cannot set up
# (PostgreSQL did not start); Docker and Podman exit 125 when the container
# itself could not start. Neither is the repro's own verdict.
IMAGE_SETUP_EXIT = 97
_IMAGE_SETUP_EXITS = (125, IMAGE_SETUP_EXIT)
_MISSING_IMAGE = re.compile(r"no such image|image not known|unable to find image",
                            re.IGNORECASE)
NO_CONTAINER_REASON = "the steps do not run in a container"
TEST_TIMEOUT = 1800
MAX_CHANGED_PATHS = 200
# (tier, the repository's command for it, its name on the card)
TIERS = (("quick", "quick_test_command", "Quick tests"), ("full", "test_command", "Tests"),
         ("gate", "gate_command", "Other checks"),
         ("heavy", "heavy_test_command", "Tests that need services"))
NEEDS_IMAGE = "needs the checker image"
BUDGET_REASON = "the spending limit ran out"
SETUP_REASON = "its work area could not be set up"
# A run that asked a person to decide (decision_requests) stops the feature
# run at once: its proposal waits for that answer and is never offered for
# approval; after the answer, the person starts a new code change.
ORIGIN_KIND = "codebase_feature"
ASKED_REASON = "it asked a person to decide, so it could not finish"
DECISION_GAP = ("The run stopped to wait for a person's decision, so this change cannot be "
                "approved. Start a new code change after the answer.")
Runner = Callable[[int, Path], object]
# (goal id of a fresh check task, its own throwaway copy of the pinned commit)
# -> its report: text ending in a JSON object, or that object.
Checker = Callable[[int, Path], object]
Reviewer = Callable[[str, str], dict]
SEVERITIES = ("blocker", "should-fix", "minor")


def _proposal_dir(name: str) -> Path:
    return vault._root(name, "proposals")


def _save(p: dict) -> None:
    body = json.dumps(p, sort_keys=True).encode()
    atomic_write_bytes(_proposal_dir(p["repo"]) / f"{p['id']}.json",
                       vault._seal(body, f"codebase/{p['repo']}/proposal/{p['id']}"))


def _load(name: str, pid: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{16}", pid):
        raise VaultError("malformed proposal id")
    try:
        raw = (_proposal_dir(name) / f"{pid}.json").read_bytes()
    except FileNotFoundError:
        raise VaultError(f"no proposal {pid} for {name!r}") from None
    return json.loads(vault._unseal(raw, f"codebase/{name}/proposal/{pid}"))


def find(pid: str) -> dict:
    for repo in vault.list_repos():
        if (_proposal_dir(repo.name) / f"{pid}.json").exists():
            return _load(repo.name, pid)
    raise VaultError(f"no proposal {pid}")


def list_proposals(name: str | None = None) -> list[dict]:
    out = []
    for repo in vault.list_repos():
        if name and repo.name != name:
            continue
        d = _proposal_dir(repo.name)
        for f in sorted(d.glob("*.json")) if d.exists() else ():
            p = _load(repo.name, f.stem)
            out.append({k: v for k, v in p.items() if k not in ("diff", "tests_output")})
    return sorted(out, key=lambda p: p["created_at"], reverse=True)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "change"


def _brief(repo: vault.Repo, title: str, description: str) -> str:
    tests = (f"The test command is `{repo.test_command}`; run it and make it pass."
             if repo.test_command else "Add or update tests for the change where the repo has them.")
    if repo.gate_command:
        tests += f" Lightwork also runs `{repo.gate_command}` (lint and other gates); make it pass."
    return (f"Implement this change in the `{repo.name}` repository (your working directory "
            f"is a checkout of branch `{repo.default_branch}` on a new feature branch).\n\n"
            f"{title}\n\n{description}\n\n{tests} Edit files in place; do not push, publish "
            "or send the code anywhere -- a human reviews and merges your change.")


def run_tests(repo: vault.Repo, work: Path, sandbox_factory=None,
              command: str | None = None) -> dict | None:
    """Run ``command`` (default: the repository's full test command) in
    ``work`` through the sandbox."""
    command = command or repo.test_command
    if not command:
        return None
    if sandbox_factory is None:
        from ..sandbox import build_sandbox
        sandbox_factory = build_sandbox
    box = sandbox_factory(workdir=str(work))
    try:
        result = box.exec(command, timeout=TEST_TIMEOUT)
    finally:
        _close(box)  # a container backend's leftovers end with the run
    output = (result.stdout or "") + (result.stderr or "")
    setup_failed = bool(getattr(result, "setup_failed", False))
    return {"command": command, "exit_code": result.exit_code,
            "passed": result.exit_code == 0 and not setup_failed,
            "setup_failed": setup_failed, "output": output[-MAX_TEST_OUTPUT_CHARS:]}


_IDENTITY = {"GIT_AUTHOR_NAME": "Lightwork", "GIT_AUTHOR_EMAIL": "lightwork@localhost",
             "GIT_COMMITTER_NAME": "Lightwork", "GIT_COMMITTER_EMAIL": "lightwork@localhost"}


def _host_commit(host: Path, work: Path, base: str, branch: str, message: str) -> str:
    """Commit the FILES of ``work`` on top of ``base`` using only host-owned git.

    The agent's working tree may contain anything, including its own ``.git``
    (hooks, config, a ``gitdir:`` pointer elsewhere). None of it is read as git
    metadata: the index lives in the host repository, git never tracks a path
    named ``.git``, and plumbing (read-tree, add, write-tree, commit-tree,
    update-ref) runs no hooks. Returns the new commit, or ``base`` when the tree
    is unchanged. The branch ref is pinned to exactly that commit."""
    env = {**_IDENTITY, "GIT_INDEX_FILE": str(host / "lw-index")}
    _git(["read-tree", base], git_dir=host, env=env)
    _git(["add", "-A", "--", "."], git_dir=host, work_tree=work, cwd=work, env=env)
    tree = _git(["write-tree"], git_dir=host, env=env).strip()
    if tree == _git(["rev-parse", f"{base}^{{tree}}"], git_dir=host).strip():
        return base
    added_links = [line for line in _git(["diff-tree", "-r", "--no-renames", base, tree],
                                         git_dir=host).splitlines()
                   if line.split(" ")[1:2] == ["160000"] and not line.startswith(":160000")]
    if added_links:
        raise VaultError("the change adds embedded git repositories; refused")
    commit = _git(["commit-tree", tree, "-p", base, "-m", message], git_dir=host, env=env).strip()
    _git(["update-ref", f"refs/heads/{branch}", commit], git_dir=host)
    return commit


def _fresh_copy(host: Path, dest: Path, commit: str, branch: str | None = None) -> Path:
    """A checkout of exactly ``commit`` (on ``branch`` when given, else
    detached) with no remote, so nothing run in it can reach the host
    repository. Tests and checks never have their copy read back; an author
    round's copy is read only by ``_host_commit``."""
    _git(["clone", "-q", "--no-hardlinks", "--no-checkout", str(host), str(dest)])
    _git(["checkout", "-q", *(["-B", branch] if branch else ["--detach"]), commit], cwd=dest)
    _git(["remote", "remove", "origin"], cwd=dest)
    return dest


@contextmanager
def _step(root: Path):
    """Stop every process the step under ``root`` started when it ends, so
    nothing it left running can write into a later round's copy."""
    from ..sandbox.local import contained_step
    with contained_step(root) as state:
        yield state


def _close(box) -> None:
    close = getattr(box, "close", None)
    if callable(close):
        close()


CONTAINER_REQUIRED = ("Code changes must run in a container, but this installation runs "
                      "commands directly on this computer. Set up a container work area, "
                      "or turn off the container requirement for code changes.")


def _runs_on_host(sandbox_factory=None) -> bool:
    """Whether feature-run steps would run on this computer without a container
    (the ``local`` backend). A backend that cannot be built here counts as
    not local: the run itself then fails on the same policy."""
    from ..sandbox import build_sandbox, fs_is_host_visible
    with vault.work_dir() as tmp:
        try:
            box = (sandbox_factory or build_sandbox)(workdir=str(tmp))
        except Exception:  # noqa: BLE001 -- the run reports the real error
            return False
        try:
            return fs_is_host_visible(box)
        finally:
            _close(box)


def _isolation(on_host: bool) -> str:
    """container | namespace (this computer, each command in its own process
    and temporary-folder namespace) | host (this computer, marker reap only)."""
    if not on_host:
        return "container"
    from ..sandbox.local import step_namespaces_available
    return "namespace" if step_namespaces_available() else "host"


def container_refusal(sandbox_factory=None) -> str | None:
    """The plain refusal when ``[codebase] require_container`` is on and the
    steps would run on this computer without a container; otherwise None."""
    if loop_settings()["require_container"] and _runs_on_host(sandbox_factory):
        return CONTAINER_REQUIRED
    return None


def _repair_brief(repo: vault.Repo, title: str, description: str, problem: str) -> str:
    return (f"Follow-up on a change you are making in the `{repo.name}` repository. Your "
            "working directory still holds your earlier edits.\n\n"
            f"The request was:\n{title}\n\n{description}\n\n{problem}\n\n"
            "Fix the cause in place. Edit files only; do not push, publish or send the "
            "code anywhere -- a human reviews and merges your change.")


def _tests_problem(tests: dict) -> str:
    from ..coding_mode import classify_failure
    kind, hint = classify_failure(tests["output"])
    what = "gate command" if tests.get("tier") == "gate" else "test command"
    return (f"The {what} `{tests['command']}` failed (exit code {tests['exit_code']}) "
            "on your last version."
            + (f"\nDominant failure class: {kind}. {hint}" if kind != "other" else "")
            + f"\n\nRecent test output:\n{tests['output'][-MAX_REPAIR_OUTPUT_CHARS:]}")


def _findings_problem(findings: list[dict]) -> str:
    def confirmed(f: dict) -> str:
        return (f" Lightwork re-ran `{f['repro']}` and it failed."
                if f.get("repro_state") == "confirmed" else "")
    return ("An independent checker found these blockers in your last version:\n"
            + "\n".join(f"- {f['what']} (how it knows: {f['how'] or 'not stated'}).{confirmed(f)}"
                        for f in findings))


def _check_brief(repo: vault.Repo, title: str, description: str, base: str,
                 files: list[str], earlier: list[dict]) -> str:
    """The checker's whole context: the request and where to read the change.
    Never the author's goal, transcript or reasoning."""
    tests = (f"The project's test command is `{repo.test_command}`."
             if repo.test_command else "The project has no test command.")
    def item(f: dict) -> str:
        line = f"- {f['id']} [{f['severity']}] {f['what']}"
        if f.get("fixed_by") == "lightwork":
            line += (" (its repro command now passes, but the author saw that command: "
                     "confirm the problem itself is gone)")
        return line
    prior = ("\n\nYour earlier findings on a previous version. Put the id of each one "
             "that is really gone in \"fixed\", and of each one still wrong in "
             "\"still_open\"; do not report them again as new findings:\n"
             + "\n".join(item(f) for f in earlier) if earlier else "")
    return (f"Independently check a proposed change to the `{repo.name}` repository. Your "
            "working directory is your own throwaway copy of exactly that change; nothing "
            "you do there reaches the proposal. Do not fix anything: find what is wrong.\n\n"
            f"The request was:\n{title}\n\n{description}\n\n"
            f"Run `git diff {base} HEAD` to read the change. Files changed: "
            f"{', '.join(files[:40]) or '(none)'}. {tests} Try to break it: run the tests "
            "yourself, write a probe, try an edge case." + prior + "\n\n"
            "For a problem a command can show, add \"repro\": one command that exits "
            "non-zero while the problem is there, and optionally \"probe_files\": the "
            f"files it needs (at most {MAX_PROBE_FILES}, {MAX_PROBE_BYTES // 1024} KB each, "
            "relative paths inside your copy). Lightwork runs it on a fresh copy of the "
            "change with those files written first. A failing repro confirms the finding; "
            "otherwise it counts as read, not ran.\n\n"
            "End with ONLY one JSON object: {\"findings\": [{\"severity\": "
            "\"blocker|should-fix|minor\", \"what\": \"<what is wrong>\", \"evidence\": "
            "\"ran|read\", \"how\": \"<the command you ran or the lines you read>\", "
            "\"repro\": \"<command>\", \"probe_files\": {\"<path>\": \"<file text>\"}}], "
            "\"fixed\": [\"<earlier id>\"], \"still_open\": [\"<earlier id>\"]}. A blocker must not merge. Say \"ran\" only "
            "when a command you ran showed the problem.")


def _report(out: object) -> dict | None:
    """The checker's JSON report (the last object with a findings list), or None."""
    if isinstance(out, dict):
        return out if isinstance(out.get("findings"), list) else None
    text, found = str(out or "")[-50_000:], None
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(text, i)
            except (ValueError, RecursionError):  # deep nesting reads as unreadable
                continue
            if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
                found = obj
    return found


def _probe_files(raw: object) -> tuple[dict[str, str], str | None]:
    """A finding's probe files, or the reason they are refused: at most three
    text files of 20 KB, relative paths inside the copy, never ``..`` or under
    ``.git``."""
    from pathlib import PurePosixPath
    if raw is None or raw == {}:
        return {}, None
    if not isinstance(raw, dict) or len(raw) > MAX_PROBE_FILES:
        return {}, f"its probe files were refused (at most {MAX_PROBE_FILES} files)"
    files: dict[str, str] = {}
    for name, text in raw.items():
        path = PurePosixPath(str(name))
        if (not isinstance(name, str) or not name.strip() or "\\" in name or "\0" in name
                or path.is_absolute() or ".." in path.parts or ".git" in path.parts
                or not path.parts or len(name) > 200):
            return {}, f"a probe file path was refused ({_safe_label(name, 80)})"
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_PROBE_BYTES:
            return {}, f"a probe file was refused ({_safe_label(name, 80)} is not text of " \
                       f"at most {MAX_PROBE_BYTES // 1024} KB)"
        files[path.as_posix()] = text
    return files, None


def _write_probes(copy: Path, files: dict[str, str]) -> str | None:
    """Write probe files into a repro's own copy; the reason when a path
    would leave it (a link in the copy can point anywhere)."""
    for name, text in files.items():
        parts = Path(name).parts
        # No link anywhere on the way, checked before any folder is made.
        if any((copy.joinpath(*parts[:i])).is_symlink() for i in range(1, len(parts) + 1)):
            return f"a probe file path was refused ({_safe_label(name, 80)})"
        target = copy.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return None


def _finding(raw: object, fid: str, checker: int | str = 1) -> dict:
    raw = raw if isinstance(raw, dict) else {"what": str(raw)}
    severity = str(raw.get("severity", "")).strip().lower()
    f = {"id": fid, "checker": checker,
         # An unreadable severity counts as the worst: it must not pass as clean.
         "severity": severity if severity in SEVERITIES else "blocker",
         "what": str(raw.get("what") or "(no description)")[:300],
         "evidence": "ran" if str(raw.get("evidence", "")).lower() == "ran" else "read",
         "how": str(raw.get("how") or "")[:300], "sent": False, "fixed": False}
    repro = raw.get("repro")
    if isinstance(repro, str) and repro.strip():
        probes, refused = _probe_files(raw.get("probe_files"))
        f.update(repro=repro.strip()[:MAX_REPRO_CHARS], probe_files=sorted(probes),
                 _probes=probes)
        if refused:  # never run: it is not Lightwork's evidence
            f.update(repro_state="not run", repro_reason=refused, evidence="read")
    return f


class DecisionPending(Exception):
    """A round's goal (or a goal below it) is waiting for a person's decision."""

    def __init__(self, decisions: list, goal_id: int) -> None:
        super().__init__("waiting for a person's decision")
        self.decisions, self.goal_id = decisions, goal_id


def _stop_if_waiting(world, goal_id: int) -> None:
    """Stop the feature run when ``goal_id`` or a goal below it asked a person
    to decide. Each round's goals are new, so any decision in that tree was
    asked in this round, even one answered before the round paused."""
    from .. import decision_requests
    decisions = decision_requests.for_tree(world, goal_id)
    if decisions:
        raise DecisionPending(decisions, goal_id)


class _Loop:
    """One feature run's rounds. The author works in its own working copy; every
    author round is committed host-side and pinned before any repository code
    runs; tests, checks and repro re-runs run on fresh copies of that pinned
    commit, so their side effects never reach the author or the proposal."""

    def __init__(self, world, repo: vault.Repo, host: Path, *, base: str,
                 branch: str, pid: str, title: str, description: str, owner: str,
                 run: Runner, checkers: list[Checker], sandbox_factory, budget,
                 repair_rounds: int, check_rounds: int, on_host: bool = True,
                 protected_checker: Checker | None = None, self_repo: bool = False) -> None:
        self.world, self.repo, self.host = world, repo, host
        self.base, self.branch, self.pid = base, branch, pid
        self.title, self.description, self.owner = title, description, owner
        self.run, self.checkers, self.sandbox_factory = run, checkers, sandbox_factory
        self.budget, self.check_rounds = budget, check_rounds
        self.repairs_left, self.repair_rounds = repair_rounds, repair_rounds
        # self.tests: the last round tier's result (quick, else full); every
        # tier's latest result, with the commit it ran on, is in self.results.
        self.head, self.bundle, self.tests = base, b"", None
        self.results: dict[str, dict] = {}
        self.review_cut_short = False
        self.setup_failed = False  # a step's isolated work area could not be set up
        self.rounds: list[dict] = []
        self.stopped: str | None = None
        settings = loop_settings()
        self.max_repros = max(0, int(settings["max_repros"]))
        self.image = str(settings["checker_image"] or "")
        # A repro is a model-written command nobody approved: it runs only in
        # a container (the checker image, or a container backend).
        self.repros_contained = bool(self.image) or not on_host
        author = _author_model() if checkers else None
        self.check: dict = {"state": "skipped" if checkers else "off", "runs": 0,
                            "off": None if checkers else
                            "settings" if not settings["checker"] else "run",
                            "max_runs": check_rounds, "commit": None, "error": None,
                            "goal_ids": [], "findings": [],
                            "checkers": [_checker_record(c, n, author)
                                         for n, c in enumerate(checkers, start=1)],
                            "image": self.image or None, "repros_skipped": False}
        # A change to a protected path (or, when allowed, to the repository the
        # running installation came from): see protect().
        self.protected_checker, self.self_repo = protected_checker, self_repo
        self.protected: dict | None = None

    def _labelled(self):
        from ..ifc import labelled_run
        return labelled_run({f"code:{self.repo.name}"}, mode=self.repo.protect)

    def _afford(self) -> bool:
        """budget.check() before every round; a spent budget stops the loop."""
        try:
            self.budget.check()
        except BudgetExceeded:
            self.stopped = "budget"
            return False
        return True

    def author(self, goal_id: int, kind: str) -> None:
        """One author round, then commit, pin and test. Every round works in a
        FRESH copy of the pinned head at a new random path, made after the
        previous step ended and removed once committed, so nothing written
        between rounds carries over. State changes only when every step
        succeeded, so a failed round leaves the last pin."""
        with vault.work_dir() as tmp, _step(tmp) as step:
            work = _fresh_copy(self.host, tmp / "work", self.head, self.branch)
            with self._labelled(), _in_loop(goal_id):
                self.run(goal_id, work)
            self.setup_failed |= step["setup_failed"]
            _stop_if_waiting(self.world, goal_id)  # nothing it left half done is committed
            if not self._afford():
                # A governed run returns normally when it hits the cap; what it
                # left half done is never committed or offered.
                raise BudgetExceeded("the spending limit ran out during an author round")
            head = _host_commit(self.host, work, self.head, self.branch,
                                f"{self.title}\n\nLightwork proposal {self.pid} (goal #{goal_id})")
        bundle, tests = self.bundle, self.tests
        if head != self.head:
            # Bundle the pinned commit BEFORE any repository code (tests) runs.
            with tempfile.TemporaryDirectory(prefix="lw-prop-") as tmp:
                out = Path(tmp) / "p.bundle"
                _git(["bundle", "create", str(out), f"{self.base}..refs/heads/{self.branch}"],
                     git_dir=self.host)
                bundle = out.read_bytes()
            tests = self._round_tier(head)
        self.head, self.bundle, self.tests = head, bundle, tests
        self.rounds.append({"kind": kind, "goal_id": goal_id, "head": head})

    def _not_run(self, tier: str, head: str, command: str, reason: str) -> dict:
        result = {"tier": tier, "command": command, "commit": head, "exit_code": None,
                  "passed": False, "setup_failed": False, "output": "", "not_run": reason}
        self.results[tier] = result
        return result

    def _run_tier(self, tier: str, head: str, command: str, box_factory=None) -> dict:
        """One tier on a fresh copy of ``head`` in a contained step, exactly
        as the tests always ran; ``budget.check()`` first."""
        if not self._afford():
            return self._not_run(tier, head, command, BUDGET_REASON)
        with vault.work_dir() as tmp, _step(tmp) as step:
            copy = _fresh_copy(self.host, tmp / "tests", head)
            if box_factory is not None:
                self._for_image(copy)
            result = run_tests(self.repo, copy, box_factory or self.sandbox_factory,
                               command=command)
            self.setup_failed |= step["setup_failed"]
        result = {**result, "tier": tier, "commit": head}
        self.results[tier] = result
        return result

    def _round_tier(self, head: str) -> dict | None:
        """After an author round: the quick tier when set, with ``{changed}``
        filled in (paths in that version, deletions left out), else the full suite. More than MAX_CHANGED_PATHS changed
        paths run the full suite instead (the quick command without them
        when there is none)."""
        quick, full = self.repo.quick_test_command, self.repo.test_command
        if quick:
            changed = self._changed(head)
            if len(changed) <= MAX_CHANGED_PATHS:
                return self._run_tier("quick", head, quick.replace(
                    vault.CHANGED, " ".join(_quote_path(f) for f in changed)))
            if not full:
                return self._run_tier("quick", head, quick.replace(vault.CHANGED, ""))
            self._not_run("quick", head, quick, f"more than {MAX_CHANGED_PATHS} files "
                                                "changed, so the full tests ran instead")
        return self._run_tier("full", head, full) if full else None

    def _changed(self, head: str) -> list[str]:
        # Paths in the version being tested: never a deleted or renamed-away one.
        return [f for f in _git(["diff", "--name-only", "--no-renames", "--diff-filter=d",
                                 "-z", self.base, head], git_dir=self.host).split("\0") if f]

    def _candidate(self, head: str) -> dict | None:
        """The full suite and the gate on ``head``, each at most once per
        commit; the first one that failed in the change, or None."""
        for tier, command in (("full", self.repo.test_command), ("gate", self.repo.gate_command)):
            if not command:
                continue
            result = self.results.get(tier)
            if not result or result["commit"] != head or result.get("not_run"):
                result = self._run_tier(tier, head, command)
            if not result["passed"]:
                return result if _repairable(result) else None
        return None

    def finish(self) -> None:
        """Before the card: the full suite and the gate again on the final
        commit when it changed since they last ran, then the heavy tier."""
        if self.head == self.base:
            return
        for tier, command in (("full", self.repo.test_command), ("gate", self.repo.gate_command)):
            result = self.results.get(tier)
            if (command and result and not result.get("not_run")
                    and result["commit"] != self.head):
                self._run_tier(tier, self.head, command)
        command = self.repo.heavy_test_command
        if not command:
            return
        if not self.image:
            self._not_run("heavy", self.head, command, NEEDS_IMAGE)
            return
        if not self._afford():  # before starting any container
            self._not_run("heavy", self.head, command, BUDGET_REASON)
            return
        problem = self._image_problem()
        if problem:
            self._not_run("heavy", self.head, command, problem)
            return
        try:
            result = self._run_tier("heavy", self.head, command, box_factory=self._box)
        except Exception as exc:  # noqa: BLE001 -- never run on this computer instead
            self._not_run("heavy", self.head, command, f"it could not start ({type(exc).__name__})")
            return
        if result.get("exit_code") in _IMAGE_SETUP_EXITS:  # the image's own set-up failed
            result.update(passed=False, setup_failed=True)

    def _repair(self, kind: str, problem: str) -> bool:
        """A follow-up goal for the author; False when the loop must stop."""
        if self.repairs_left <= 0 or not self._afford():
            return False
        self.repairs_left -= 1
        n = self.repair_rounds - self.repairs_left
        root = self.rounds[0]["goal_id"]
        gid = self.world.create_goal(
            f"[{self.repo.name}] {self.title} (repair {n})",
            _repair_brief(self.repo, self.title, self.description, problem),
            parent_id=root, owner=self.owner, execution_principal=self.owner)
        try:
            _mark_step(self.world, gid, self.pid)
            self.author(gid, kind)
        except DecisionPending:
            raise
        except Exception as exc:  # noqa: BLE001 -- the last pinned version stands
            self.stopped = "budget" if isinstance(exc, BudgetExceeded) else "error"
            _fail_goal(self.world, gid, exc)
            return False
        return True

    def repair_tests(self) -> None:
        """Repair until the round tier passes, then run the full suite and the
        gate on the same pinned commit; a failure there is a repair too."""
        while not self.stopped and self.head != self.base:
            failed = self.tests
            if failed is not None and not failed["passed"]:
                if not _repairable(failed):  # nothing in the change to repair
                    return
            else:
                failed = self._candidate(self.head)
                if failed is None:
                    return
            kind = "gate" if failed.get("tier") == "gate" else "tests"
            if not self._repair(kind, _tests_problem(failed)):
                return

    def _box(self, workdir: str):
        """The sandbox for a repro re-run: the checker image when one is set
        (never this computer instead), else the tests' sandbox."""
        if self.image:
            return image_sandbox(self.image, workdir)
        if self.sandbox_factory is not None:
            return self.sandbox_factory(workdir=workdir)
        from ..sandbox import build_sandbox
        return build_sandbox(workdir=workdir)

    def _image_problem(self) -> str | None:
        """Why the checker image cannot be used here, or None. Tried once with
        a command that does nothing, before any checker runs."""
        if not self.image:
            return None
        with vault.work_dir() as tmp:
            probe = tmp / "probe"  # the private work folder itself stays root-only
            probe.mkdir()
            self._for_image(probe)
            try:
                box = self._box(str(probe))
            except Exception as exc:  # noqa: BLE001 -- reported, never a host run
                return f"the checker image could not be used: {_safe_label(exc, 160)}"
            try:
                result = box.exec("true", timeout=300)
            except Exception as exc:  # noqa: BLE001
                return f"the checker image could not be used: {_safe_label(exc, 160)}"
            finally:
                _close(box)
        if result.exit_code != 0 or getattr(result, "setup_failed", False):
            said = next((line.strip() for line in ((result.stderr or "") + "\n"
                                                   + (result.stdout or "")).splitlines()
                         if line.strip()), "")[:160]
            if result.exit_code == 125 and _MISSING_IMAGE.search(said):
                engine = "podman" if type(box).__name__.startswith("Podman") else "docker"
                return (f"the checker image {self.image} is not on this computer. An "
                        f"administrator can build it with `{engine} build -t {self.image} "
                        f"deploy/checker` or pull it with `{engine} pull {self.image}`")
            return (f"the checker image could not be used (exit code {result.exit_code}"
                    + (f": {_safe_label(said, 160)})" if said else ")"))
        return None

    def _for_image(self, path: Path) -> None:
        """On a root host the image runs as an ordinary user: hand it the copy."""
        if self.image and _host_is_root():
            _give_to_image_user(path)

    def _look(self, checker: Checker, n: int) -> dict | None:
        """One look by checker ``n`` on its own copy; None when it did not run.
        Its brief lists only its own earlier findings, never another's."""
        if not self._afford():
            return None
        many = len(self.checkers) > 1
        # Its own open findings, and those only a repro re-run calls fixed:
        # the author saw that command, so the checker must confirm the fix.
        earlier = [f for f in self.check["findings"]
                   if f.get("checker", 1) == n and (not f["fixed"] or _unconfirmed(f))]
        gid = self._check_goal(f"Check: {self.title}" + (f" (checker {n})" if many else ""),
                               earlier)
        self.check["goal_ids"].append(gid)
        who = f"checker {n}: " if many else ""
        try:
            out = self._check_copy(checker, gid)
        except DecisionPending:
            self.check["error"] = f"{who}{ASKED_REASON}"
            self.check["checkers"][n - 1]["error"] = ASKED_REASON
            raise
        except BudgetExceeded as exc:
            self.stopped = "budget"
            _fail_goal(self.world, gid, exc)
            return None
        except Exception as exc:  # noqa: BLE001 -- recorded: the change was not checked
            self.check["error"] = f"{who}it stopped with {type(exc).__name__}"
            self.check["checkers"][n - 1]["error"] = f"it stopped with {type(exc).__name__}"
            _fail_goal(self.world, gid, exc)
            return None
        if not self._afford():
            self.check["cut_short"] = True  # it ran, but its report is not used
            return None
        report = _report(out)
        if report is None:
            self.check["error"] = f"{who}its report could not be read"
            self.check["checkers"][n - 1]["error"] = "its report could not be read"
        self._count_only(gid, report)
        return report

    def _check_goal(self, what: str, earlier: list[dict]) -> int:
        """A fresh check task: the request and where to read the change, never
        the author's goal, transcript or reasoning."""
        files = [f for f in _git(["diff", "--name-only", "-z", self.base, self.head],
                                 git_dir=self.host).split("\0") if f]
        gid = self.world.create_goal(
            f"[{self.repo.name}] {what}",
            _check_brief(self.repo, self.title, self.description, self.base, files, earlier),
            owner=self.owner, execution_principal=self.owner)
        _mark_step(self.world, gid, self.pid)
        return gid

    def _check_copy(self, checker: Checker, gid: int) -> object:
        """Run ``checker`` on its own throwaway copy of the pinned head."""
        with vault.work_dir() as tmp, _step(tmp) as step:
            copy = _fresh_copy(self.host, tmp / "check", self.head)
            self._for_image(copy)
            with self._labelled(), _in_loop(gid):
                out = checker(gid, copy)
            self.setup_failed |= step["setup_failed"]
        _stop_if_waiting(self.world, gid)  # never read as a clean look
        return out

    def protect(self) -> None:
        """Whether the final change is protected: it touches a protected path
        (both sides of a rename count) or, when allowed, the repository the
        running installation came from (then the whole repository is)."""
        if self.head == self.base:
            return
        paths = [f for f in _git(["diff", "--name-only", "--no-renames", "-z", self.base,
                                  self.head], git_dir=self.host).split("\0") if f]
        matched = vault.protected_matches(self.repo.protected_paths, paths)
        if not matched and not self.self_repo:
            return
        self.protected = {"paths": matched[:MAX_PROTECTED_LISTED], "count": len(matched),
                          "self": self.self_repo, "model": None, "problem": None,
                          "state": "not run", "reason": None, "commit": None,
                          "goal_id": None, "findings": []}
        self._second_check()

    def _second_check(self) -> None:
        """For a protected change, after the normal checkers: one more
        independent checker, whose model must be of a different provider family
        from the author's and every normal checker's. Charged to the same
        budget; it looks once, at the final version."""
        rec = self.protected
        assert rec is not None
        checker = self.protected_checker
        model = getattr(checker, "model", None) if checker is not None else None
        rec["model"] = str(model) if model else None
        rec["problem"] = _family_problem(rec["model"], _author_model(),
                                         [c.get("model") for c in self.check["checkers"]])
        if rec["problem"] or checker is None or not _named(self.owner):
            return  # it could not be approved anyway: spend nothing on it
        if self.stopped or not self._afford():
            rec["reason"] = BUDGET_REASON if self.stopped in (None, "budget") else \
                "the run stopped early"
            return
        gid = rec["goal_id"] = self._check_goal(f"Protected check: {self.title}", [])
        try:
            out = self._check_copy(checker, gid)
        except DecisionPending:
            rec["reason"] = ASKED_REASON
            raise
        except BudgetExceeded as exc:
            self.stopped, rec["reason"] = "budget", BUDGET_REASON
            _fail_goal(self.world, gid, exc)
            return
        except Exception as exc:  # noqa: BLE001 -- recorded: the change was not checked
            rec["reason"] = f"it stopped with {type(exc).__name__}"
            _fail_goal(self.world, gid, exc)
            return
        if not self._afford():
            rec["reason"] = BUDGET_REASON  # it ran, but its report is not used
            return
        report = _report(out)
        self._count_only(gid, report)
        if report is None:
            rec["reason"] = "its report could not be read"
            return
        findings = [_finding(raw, f"p.{i}", "protected") for i, raw in
                    enumerate(report["findings"][:MAX_FINDINGS], start=1)]
        self._confirm(findings)
        rec.update(state="ran", commit=self.head, findings=[
            {k: v for k, v in f.items() if k not in ("sent", "fixed") and not k.startswith("_")}
            | {"status": "not attempted"} for f in findings])

    def _count_only(self, goal_id: int, report: dict | None) -> None:
        """Finding text can quote vaulted code: the check task's own result
        (goal pages, later reads) keeps only counts; the text stays in the
        sealed proposal, which only administrators read."""
        found = "its report could not be read" if report is None else \
            f"{len(report['findings'][:MAX_FINDINGS])} finding(s)"
        try:
            goal = self.world.get_goal(goal_id)
            self.world.set_goal_status(
                goal_id, goal.status if goal is not None else "done",
                result=f"Independent check of Lightwork proposal {self.pid}: {found}. "
                       f"Read them with maverick code show {self.pid}.")
        except Exception:  # noqa: BLE001 -- the proposal still records the check
            pass

    def _look_all(self) -> list[tuple[int, dict]]:
        """Every checker looks at the pinned head, each on its own copy."""
        got = []
        for n, checker in enumerate(self.checkers, start=1):
            report = self._look(checker, n)
            if report is not None:
                got.append((n, report))
                self.check["checkers"][n - 1]["commit"] = self.head
            if self.stopped or self.check.get("cut_short"):
                break
        return got

    def verify(self) -> None:
        """Test repairs, then checker looks with blocker repairs in between.
        After each look Lightwork re-runs the new findings' repros; after each
        repair, every confirmed repro on the repaired commit."""
        self.repair_tests()
        if not self.checkers or self.head == self.base:
            return
        problem = self._image_problem()
        if problem:
            self.check["error"] = problem
            return
        while self.check["runs"] < self.check_rounds and not self.stopped:
            got = self._look_all()
            if not got:
                break
            self.check["runs"] += 1
            complete = len(got) == len(self.checkers)
            if complete:
                self.check["commit"] = self.head
            new: list[dict] = []
            for n, report in got:
                new += self._record(report, n)
            self._confirm(new)
            open_blockers = [f for f in self.check["findings"]
                             if f["severity"] == "blocker" and not f["fixed"]]
            if not (complete and open_blockers) or self.check["runs"] >= self.check_rounds:
                break
            if not self._repair("check", _findings_problem(open_blockers)):
                break
            for f in open_blockers:
                f["sent"] = True
            self.repair_tests()
            self._recheck()

    def _record(self, report: dict, n: int) -> list[dict]:
        """Checker ``n``'s report: its word on its own earlier findings (never
        on one Lightwork confirmed), then its new findings."""
        fixed, still = (
            {str(i) for i in report.get(key) or () if isinstance(i, (str, int))}
            if isinstance(report.get(key) or (), (list, tuple)) else set()
            for key in ("fixed", "still_open"))
        for f in self.check["findings"]:
            if f.get("checker", 1) != n:
                continue
            if _unconfirmed(f):  # its repro passed after a repair the author steered
                if f["id"] in still:
                    f.update(fixed=False, fixed_by=None, checker_confirmed=False)
                elif f["id"] in fixed:
                    f["checker_confirmed"] = True
            elif f.get("repro_state") != "confirmed" and not f["fixed"] and f["id"] in fixed:
                f["fixed"], f["fixed_by"] = True, "checker"
        runs, prefix = self.check["runs"], "" if n == 1 else f"{n}-"
        new = [_finding(raw, f"{prefix}{runs}.{i}", n) for i, raw in
               enumerate(report["findings"][:MAX_FINDINGS], start=1)]
        self.check["findings"] += new
        return new

    def _confirm(self, findings: list[dict]) -> None:
        """Lightwork re-runs each new finding's repro, at most ``max_repros``
        per look: a non-zero exit confirms it; exit zero, a timeout or a work
        area that could not be set up leaves it not reproduced, read only."""
        ran = 0
        for f in findings:
            if not f.get("repro") or f.get("repro_state"):
                continue
            if not self.repros_contained:
                f.update(repro_state="not re-run", repro_reason=NO_CONTAINER_REASON)
                self.check["repros_skipped"] = True
                continue
            if ran >= self.max_repros:
                f.update(repro_state="not re-run", repro_reason=(
                    f"the limit of {self.max_repros} re-runs per look was reached"))
                continue
            if not self._charge():
                f.update(repro_state="not re-run", repro_reason="the spending limit ran out")
                continue
            ran += 1
            outcome, reason = self._repro(f, self.head)
            if outcome == "failed":
                f.update(repro_state="confirmed",
                         recheck={"commit": self.head, "result": "failed"})
            elif outcome in ("passed", "timeout"):
                f.update(repro_state="not reproduced", repro_reason=reason, evidence="read")
            else:  # nothing ran: a refused probe or a work area that was not set up
                f.update(repro_state="not run", repro_reason=reason, evidence="read")

    def _recheck(self) -> None:
        """After a repair, every confirmed repro runs on the new commit: exit
        zero is fixed, whatever the checker says; anything else stays open."""
        for f in self.check["findings"]:
            if f.get("repro_state") != "confirmed" or f["recheck"]["commit"] == self.head:
                continue
            f.update(fixed=False, fixed_by=None, checker_confirmed=None)
            if not self._charge():
                f["recheck"] = {"commit": self.head, "result": "not re-run",
                                "reason": "the spending limit ran out"}
                continue
            outcome, reason = self._repro(f, self.head)
            f["recheck"] = {"commit": self.head, "result": outcome, "reason": reason}
            if outcome == "passed":
                f["fixed"], f["fixed_by"] = True, "lightwork"

    def _charge(self) -> bool:
        """budget.check() before a re-run, which counts as one tool call; a
        call over the cap does not run and stops the loop."""
        if self.stopped or not self._afford():
            return False
        try:
            self.budget.record_tool_call()
        except BudgetExceeded:
            self.stopped = "budget"
            return False
        return True

    def _repro(self, f: dict, head: str) -> tuple[str, str]:
        """Run one repro on a fresh copy of ``head`` with its probe files: the
        same contained step, sandbox and network policy as the tests (or the
        checker image). (outcome, plain reason)."""
        try:
            with vault.work_dir() as tmp, _step(tmp) as step:
                copy = _fresh_copy(self.host, tmp / "repro", head)
                refused = _write_probes(copy, f.get("_probes") or {})
                if refused:
                    return "setup", refused
                self._for_image(copy)
                box = self._box(str(copy))
                started = time.monotonic()
                try:
                    result = box.exec(f["repro"], timeout=REPRO_TIMEOUT)
                finally:
                    _close(box)
                elapsed = time.monotonic() - started
                setup = (step["setup_failed"] or bool(getattr(result, "setup_failed", False))
                         or (bool(self.image) and result.exit_code in _IMAGE_SETUP_EXITS))
        except Exception as exc:  # noqa: BLE001 -- a re-run that cannot start shows nothing
            return "setup", f"it could not start ({type(exc).__name__})"
        if setup:
            return "setup", "its work area could not be set up"
        if result.exit_code == 124 or elapsed >= REPRO_TIMEOUT:
            return "timeout", "it ran out of time"
        if result.exit_code == 0:
            return "passed", "it passed"
        return "failed", ""

    def tier_record(self) -> tuple[dict | None, dict, str | None]:
        """(the full suite's result, each tier's state ON THE FINAL COMMIT,
        the tiers' output). Only the full suite passing on the final commit
        makes ``passed`` true; a quick pass never does."""
        tiers, outputs = {}, []
        for tier, key, label in TIERS:
            command = getattr(self.repo, key)
            result = self.results.get(tier)
            if not command:
                tiers[tier] = {"state": "not configured"}
                continue
            reason = None
            if result is None or result["commit"] != self.head:
                state, reason = "not run", self._why_not(result)
            elif result.get("not_run") or result.get("setup_failed"):
                state = "not run"
                reason = result.get("not_run") or SETUP_REASON
            else:
                state = "passed" if result["passed"] else "failed"
            tiers[tier] = {"state": state, "reason": reason, "command": command,
                           "exit_code": None if result is None else result["exit_code"]}
            if result is not None and result.get("output") and result["commit"] == self.head:
                outputs.append(f"--- {label}: `{result['command']}` ---\n{result['output']}")
        tests = None
        if self.repo.test_command:
            full = self.results.get("full") or {}
            tests = {"command": full.get("command", self.repo.test_command),
                     "exit_code": full.get("exit_code"), "commit": full.get("commit"),
                     "setup_failed": bool(full.get("setup_failed")),
                     "passed": tiers["full"]["state"] == "passed",
                     "ran": tiers["full"]["state"] in ("passed", "failed")}
        return tests, tiers, "\n\n".join(outputs) or None

    def _why_not(self, result: dict | None) -> str:
        """Why a configured tier has no result on the final commit."""
        if result is not None and result.get("not_run"):
            return result["not_run"]
        if result is not None:
            return "it ran only on an earlier version"
        if self.stopped == "budget":
            return BUDGET_REASON
        if self.stopped == "decision":
            return "the run stopped for a person's decision"
        if self.stopped:
            return "a repair round failed"
        if self.repo.quick_test_command:
            return "the quick tests did not pass, and no repair rounds were left"
        return "the run stopped before it"

    def record(self) -> tuple[dict, dict]:
        check = dict(self.check)
        check["state"] = ("ran" if check["runs"] else "failed" if check["error"]
                          else check["state"])
        check["findings"] = [{k: v for k, v in f.items()
                              if k not in ("sent", "fixed") and not k.startswith("_")}
                             | {"status": "fixed" if f["fixed"] else
                                "still open" if f["sent"] else "not attempted"}
                             for f in check["findings"]]
        return {"used": self.repair_rounds - self.repairs_left,
                "allowed": self.repair_rounds}, check


def _repairable(result: dict) -> bool:
    """A tier that ran and failed: something in the change to repair (not a
    work area that could not be set up, nor a tier that did not run)."""
    return not result["passed"] and not result.get("setup_failed") \
        and not result.get("not_run")


def _quote_path(path: str) -> str:
    """A changed path for ``{changed}``: shell-quoted, never read as an option."""
    import shlex
    return shlex.quote(f"./{path}" if path.startswith("-") else path)


def _unconfirmed(f: dict) -> bool:
    """Fixed only because its repro passed after a repair (the author saw the
    command), and no later look confirmed it yet."""
    return bool(f.get("fixed")) and f.get("fixed_by") == "lightwork" \
        and f.get("checker_confirmed") is not True


def _repro_only_fixed(f: dict) -> bool:
    """A saved finding called fixed only by its repro passing after a repair,
    with no later look confirming it."""
    return f.get("status") == "fixed" and f.get("fixed_by") == "lightwork" \
        and f.get("checker_confirmed") is not True


def _author_model() -> str | None:
    """The author's model (the ``orchestrator`` role), for the family check."""
    try:
        from ..llm import model_for_role
        return model_for_role("orchestrator") or None
    except Exception:  # noqa: BLE001 -- the card then says it could not compare
        return None


def _checker_record(checker: Checker, n: int, author: str | None) -> dict:
    """Which model checker ``n`` uses and whether it shares the author's family."""
    model = getattr(checker, "model", None)
    model = str(model) if model else None
    same = None
    if model and author:
        from ..verifier import _same_family
        same = _same_family(model, author)
    return {"n": n, "model": model, "same_family": same, "commit": None}


# family -> the names its models start with (a whole name: followed by the
# end, a separator or a version number, never more letters).
_FAMILIES = {
    "anthropic": ("claude",),
    "openai": ("gpt", "chatgpt", "o1", "o3", "o4", "davinci"),
    "google": ("gemini", "gemma", "palm"),
    "meta": ("llama", "codellama"),
    "mistral": ("mistral", "mixtral", "codestral", "magistral", "ministral", "pixtral",
                "devstral"),
    "deepseek": ("deepseek",),
    "alibaba": ("qwen", "qwq"),
    "cohere": ("command", "aya"),
    "xai": ("grok",),
    "microsoft": ("phi",),
    "amazon": ("nova", "titan"),
    "moonshot": ("kimi",),
    "zhipu": ("glm",),
}
_NAME = {stem: family for family, stems in _FAMILIES.items() for stem in stems}
_STEM = re.compile(r"(" + "|".join(sorted(map(re.escape, _NAME), key=len, reverse=True))
                   + r")(?=$|[-_.:\s]|\d)")
_ORGS = frozenset({"anthropic", "openai", "google", "meta", "meta-llama", "mistralai", "mistral",
                   "deepseek", "deepseek-ai", "qwen", "alibaba", "cohere", "x-ai", "xai",
                   "microsoft", "amazon", "moonshotai", "z-ai", "zhipu", "ai21"})
def model_family(model: object) -> str | None:
    """The vendor family of a model spec, or None when it cannot be told.

    The model's own name decides, after any gateway (``openrouter:``,
    ``bedrock:``, ``vertex:``...), organisation (``anthropic/``) or Bedrock
    region and vendor (``us.anthropic.``): it must START with a known model
    name (``claude-``, ``gpt-``, ``o3``, ``gemini-``, ``llama3``...). A name
    that also names another vendor's model anywhere (a distillation) cannot
    be compared. A name it does not know cannot be compared either, whatever
    its provider prefix (``openai:my-ft``); OpenAI's fine-tune form
    ``ft:<base model>:...`` reads as its base model. Stricter than
    :func:`maverick.verifier._same_family`, which other callers keep."""
    text = str(model or "").strip().lower()
    if not text:
        return None
    provider, _, name = text.partition(":") if ":" in text else ("", "", text)
    if provider == "ft" or name.startswith("ft:"):
        # OpenAI's own fine-tune form, ft:<base model>:<org>:...: its base decides.
        name = (name if provider == "ft" else name[3:]).split(":", 1)[0]
    name = name.rsplit("/", 1)[-1]
    name = re.sub(r"^(?:us|eu|apac|global|us-gov)\.", "", name)
    head, dot, rest = name.partition(".")
    if dot and head in _ORGS:
        name = rest
    found = _STEM.match(name)
    others = {_NAME[m.group(1)] for m in _STEM.finditer(name)
              if m.start() == 0 or name[m.start() - 1] in "-_.: "}
    if not found:
        return None  # a name Lightwork does not know: never its provider's family
    family = _NAME[found.group(1)]
    return family if others <= {family} else None


def _family_problem(model: str | None, author: str | None,
                    checkers: list[str | None]) -> str | None:
    """Why the second checker cannot vouch for a protected change, or None:
    unset | same_family (as the author or a normal checker) | uncompared
    (any family that cannot be told counts as not comparable)."""
    if not model:
        return "unset"
    mine = model_family(model)
    others = [model_family(o) for o in (author, *checkers)]
    if mine is None or any(o is None for o in others):
        return "uncompared"
    return "same_family" if mine in others else None


def _fail_goal(world, goal_id: int, exc: BaseException) -> None:
    try:
        world.set_goal_status(goal_id, "failed",
                              result=f"feature proposal failed: {type(exc).__name__}")
    except Exception:  # noqa: BLE001 -- the original error is what matters
        pass


def feature_budget(max_dollars: float | None = None):
    """One budget for a whole feature run (every author and checker round).
    Honors [budget] config and the per-goal defaults; a bare
    Budget(max_dollars=None) would run with no cap of any kind. An explicit
    max_dollars still wins."""
    from ..budget import budget_from_config
    from ..runner import goal_budget_defaults
    return budget_from_config(defaults=goal_budget_defaults(), max_dollars=max_dollars)


def loop_settings() -> dict:
    """``[codebase]`` repair_rounds / checker / check_rounds, with their defaults."""
    from ..config import CODEBASE_LOOP_DEFAULTS, get_codebase
    cfg = get_codebase()
    return {k: cfg.get(k, v) for k, v in CODEBASE_LOOP_DEFAULTS.items()}


def _review(loop: _Loop, reviewer: Reviewer | None, brief: str, diff: str) -> dict | None:
    """The advisory diff review, charged to the run's budget; skipped once the
    budget stopped the run."""
    if not (reviewer and diff) or loop.stopped:
        return None
    try:
        loop.budget.check()
        return reviewer(brief, diff)
    except BudgetExceeded:
        loop.review_cut_short = True  # every round ran; only the review was cut short
        return None


SELF_REFUSAL = ("This code project is the Lightwork installation that runs these changes, so "
                "Lightwork will not change it. Run the factory from a separate installation "
                "pinned to a released version.")


def _installation_checkout(package_dir: Path | None = None) -> Path | None:
    """The git checkout the running ``maverick`` package was imported from
    (an editable or source install), or None: a wheel lives in
    ``site-packages``, outside any checkout, even inside a checkout's venv."""
    if package_dir is None:
        import maverick
        package_dir = Path(maverick.__file__).resolve().parent
    for folder in (package_dir, *package_dir.parents):
        if folder.name in ("site-packages", "dist-packages"):
            return None
        if (folder / ".git").exists():
            return folder
    return None


def _same_place(url: str) -> str:
    """A git address reduced to host and path (scheme, user, port, ``.git``
    and case of the host dropped), or a local path resolved."""
    from urllib.parse import urlsplit
    text = url.strip()
    scp = re.fullmatch(r"(?:[^@/\s]+@)?([^:/\s]+):(?!//)(.+)", text)
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme == "file":
            return str(Path(parts.path).resolve())
        host, path = (parts.hostname or "").lower(), parts.path
    elif scp and not Path(text).exists():
        host, path = scp.group(1).lower(), scp.group(2)
    else:
        return str(Path(text).expanduser().resolve())
    path = path.strip("/")
    return f"{host}/{path.removesuffix('.git')}"


def _roots(git_dir: Path | None = None, cwd: Path | None = None, ref: str = "HEAD",
           safe: Path | None = None) -> set[str]:
    """First commits of ``ref``; raises :class:`VaultError` when git cannot say."""
    trust = ["-c", f"safe.directory={safe}"] if safe is not None else []
    return set(_git([*trust, "rev-list", "--max-parents=0", ref], git_dir=git_dir,
                    cwd=cwd).split())


def is_installation(repo: vault.Repo, host: Path) -> bool:
    """Whether ``repo`` is the source of the running installation: the
    installed ``maverick`` package is imported from a git checkout (not a
    wheel) and that checkout is the repository's source path, has a remote
    at the same address, or shares a first commit with the vaulted default
    branch (a mirror, a fork or another address of the same history).

    The checkout is read with ``safe.directory`` set to it, so one owned by
    another user still answers; anything git cannot answer about a checkout
    that was found counts as the installation (fail closed)."""
    checkout = _installation_checkout()
    if checkout is None:
        return False
    if _same_place(repo.source) == _same_place(str(checkout)):
        return True
    try:
        remotes = _git(["-c", f"safe.directory={checkout}", "remote", "-v"], cwd=checkout)
    except VaultError:
        return True
    places = {_same_place(line.split()[1]) for line in remotes.splitlines()
              if len(line.split()) >= 2}
    if _same_place(repo.source) in places:
        return True
    try:
        ours = _roots(git_dir=host, ref=f"refs/heads/{repo.default_branch}")
        theirs = _roots(cwd=checkout, safe=checkout)
    except VaultError:
        return True
    return bool(ours & theirs)


def self_change_refusal(name: str) -> str | None:
    """The plain refusal when ``name`` is the running installation's own
    repository and ``[codebase] allow_self_changes`` is off; otherwise None."""
    if loop_settings()["allow_self_changes"]:
        return None
    try:
        repo = vault.get(name)
        with vault.host_repo(name) as host:
            return SELF_REFUSAL if is_installation(repo, host) else None
    # failure-policy: fail_open -- an early answer only; propose() checks again and refuses
    except Exception:  # noqa: BLE001
        return None


def _mark_step(world, goal_id: int, pid: str) -> None:
    """Record a goal as a code-change step, before it runs; an origin it
    already has is kept. A mark that cannot be written raises, so nothing
    runs unmarked (decision_requests.feature_start_refusal)."""
    if world.tenant_query("SELECT 1 FROM goal_origins o WHERE o.goal_id = ? AND "
                          "{tenant_goal:o.goal_id}", (int(goal_id),)):
        return
    world.record_goal_origin(goal_id, ORIGIN_KIND, pid)


@contextmanager
def _in_loop(goal_id: int):
    """This loop's own run of ``goal_id``: the one place a marked step starts."""
    from .. import decision_requests
    token = decision_requests.FEATURE_LOOP.set(
        decision_requests.FEATURE_LOOP.get() | {int(goal_id)})
    try:
        yield
    finally:
        decision_requests.FEATURE_LOOP.reset(token)


RUNNING_LINE = "This change is still being built."
STOPPED_LINE = ("This change stopped before it finished, for example because Lightwork "
                "restarted. Start a new code change.")


def _proc_identity(pid: int) -> tuple[str, str] | None:
    """(boot id, start time) of process ``pid`` from ``/proc``, so a reused
    process number or a restarted computer never reads as the same process;
    None where ``/proc`` cannot tell (another system, or no such process)."""
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        stat = Path(f"/proc/{int(pid)}/stat").read_text()
    except (OSError, ValueError):
        return None
    fields = stat.rsplit(")", 1)[-1].split()
    return (boot, fields[19]) if len(fields) > 19 else None  # field 22: start time


def _wall_cap(budget) -> float:
    """The run's wall-time cap: the budget's, else the configured default."""
    from ..runner import DEFAULT_MAX_WALL_SECONDS, goal_budget_defaults
    cap = getattr(budget, "max_wall_seconds", None) or \
        goal_budget_defaults()["max_wall_seconds"] or DEFAULT_MAX_WALL_SECONDS
    return float(cap)


def _running_record(pid: str, name: str, title: str, branch: str, base: str, owner: str,
                    budget) -> dict:
    """The record a change keeps while it is built, replaced by its proposal
    when it ends; who runs it (this computer and process) and until when."""
    import socket
    now, cap = time.time(), _wall_cap(budget)
    identity = _proc_identity(os.getpid())
    return {"id": pid, "repo": name, "title": title, "goal_id": None, "branch": branch,
            "base": base, "head": base, "files": [], "diff": "", "tests_output": None,
            "tests": None, "review": None, "check": None, "status": "running",
            "approval_id": None, "created_at": now, "merged_at": None,
            "owner": owner or None, "protected": None, "decision": None,
            "host": socket.gethostname(), "process": os.getpid(),
            "boot_id": identity[0] if identity else None,
            "process_start": identity[1] if identity else None,
            "wall_cap": cap, "deadline": now + cap}


def _run_gone(p: dict) -> bool:
    """Whether a change left \"running\" is no longer being built: past its
    time cap anywhere, or, on this computer, its process is not the very one
    that started it (same boot, same process start time; a reused process
    number or a restart does not count). Without ``/proc`` the cap decides."""
    import socket
    if time.time() > float(p.get("deadline") or 0):
        return True
    if p.get("host") != socket.gethostname() or not isinstance(p.get("process"), int):
        return False
    now = _proc_identity(int(p["process"]))
    if now is None:
        return _proc_identity(os.getpid()) is not None  # /proc works: that process is gone
    return now != (p.get("boot_id"), p.get("process_start"))


def _end_run(world, pid: str, record: dict | None) -> None:
    """A change that raised: its record reads stopped, and nothing it queued starts."""
    _close_queued(world, pid)
    if record is not None:
        try:
            _save({**record, "status": "stopped"})
        except Exception:  # noqa: BLE001 -- the process ending shows it as stopped anyway
            pass


def _close_queued(world, pid: str) -> None:
    """Cancel every goal still waiting to start below this change's steps:
    its private copy of the code is gone, so none of them may run now."""
    from ..decision_requests import FEATURE_RESTARTS
    try:
        rows = world.tenant_query(
            "WITH RECURSIVE down(id) AS (SELECT o.goal_id FROM goal_origins o WHERE o.kind = ? "
            "AND o.ref = ? UNION SELECT g.id FROM goals g JOIN down d ON g.parent_id = d.id) "
            "SELECT g.id FROM goals g JOIN down ON g.id = down.id WHERE g.status = 'pending' "
            "AND {tenant_goal:g.id}", (ORIGIN_KIND, pid))
        for row in rows:
            world.set_goal_status(int(row[0]), "cancelled", result=FEATURE_RESTARTS)
    except Exception:  # noqa: BLE001 -- the start check refuses them anyway
        import logging
        logging.getLogger(__name__).warning("feature run %s: queued goals not closed", pid)


def _hold(world, decisions: list, goal_id: int, pid: str) -> list[dict]:
    """The decisions a feature run stopped for, as the proposal records them.
    The round's goal and every waiting goal are marked as feature-run steps,
    so no answer or restart ever runs them outside their private copy
    (decision_requests.resume_refusal)."""
    for marked in dict.fromkeys([goal_id, *(d.goal_id for d in decisions)]):
        try:
            _mark_step(world, marked, pid)
        except Exception:  # noqa: BLE001 -- its round was marked before it ran
            import logging
            logging.getLogger(__name__).warning("feature run %s: goal #%s not marked", pid,
                                                marked)
    return [{"id": d.id, "goal_id": d.goal_id, "question": d.question,
             "open": d.status == "open"} for d in decisions]


def propose(world, name: str, title: str, description: str, run: Runner, *,
            reviewer: Reviewer | None = None,
            checker: Checker | list[Checker] | None = None,
            sandbox_factory=None, owner: str = "", budget=None,
            repair_rounds: int | None = None, check_rounds: int | None = None,
            protected_checker: Checker | None = None) -> dict:
    """Run a feature swarm, repair and check its change, and park it for
    human approval. ``budget`` is the one cap for every round (the caller's
    runner and checkers must charge the same object); ``None`` builds one from
    configuration. ``checker`` is one checker or a list of independent ones
    (:func:`default_checkers`). Round limits default to ``[codebase]``.
    ``protected_checker`` (:func:`default_protected_checker`) is the second,
    cross-family checker a change to a protected path needs; ``owner`` is the
    person who started the run, who may not approve a protected change."""
    repo = vault.get(name)
    settings = loop_settings()
    on_host = _runs_on_host(sandbox_factory)
    if settings["require_container"] and on_host:
        raise VaultError(CONTAINER_REQUIRED)
    budget = budget if budget is not None else feature_budget()
    checkers = ([] if checker is None else list(checker) if isinstance(checker, (list, tuple))
                else [checker])
    pid = secrets.token_hex(8)
    branch = f"lightwork/{_slug(title)}-{pid[:6]}"
    goal_id, waiting, record = None, None, None
    try:
        with vault.host_repo(name) as host:
            base = _git(["rev-parse", "--verify", f"refs/heads/{repo.default_branch}"],
                        git_dir=host).strip()
            self_repo = is_installation(repo, host)
            if self_repo and not settings["allow_self_changes"]:
                raise VaultError(SELF_REFUSAL)
            record = _running_record(pid, name, title, branch, base, owner, budget)
            _save(record)  # the Code page shows the change while it is built
            loop = _Loop(world, repo, host, base=base, branch=branch, pid=pid,
                         title=title, description=description, owner=owner, run=run,
                         checkers=checkers, sandbox_factory=sandbox_factory, budget=budget,
                         on_host=on_host, protected_checker=protected_checker,
                         self_repo=self_repo,
                         repair_rounds=max(0, int(settings["repair_rounds"] if repair_rounds
                                                  is None else repair_rounds)),
                         check_rounds=max(1, int(settings["check_rounds"] if check_rounds
                                                 is None else check_rounds)))
            budget.check()
            goal_id = world.create_goal(f"[{name}] {title}", _brief(repo, title, description),
                                        owner=owner, execution_principal=owner)
            _mark_step(world, goal_id, pid)
            try:
                with _exact_models(repo, self_repo):
                    loop.author(goal_id, "author")
                    loop.verify()
                    loop.protect()
                    loop.finish()
            except DecisionPending as pause:  # what was spent stays charged
                loop.stopped = "decision"
                waiting = _hold(world, pause.decisions, pause.goal_id, pid)
            head, changed = loop.head, loop.head != base
            diff = files = None
            if changed:
                diff = _git(["diff", "--no-ext-diff", "--no-textconv", base, head], git_dir=host)
                files = [f for f in _git(["diff", "--name-only", "-z", base, head],
                                         git_dir=host).split("\0") if f]
    except BaseException as exc:
        if goal_id is not None:
            _fail_goal(world, goal_id, exc)
        _end_run(world, pid, record)
        if isinstance(exc, BudgetExceeded):
            raise VaultError("the spending limit ran out before the first version was "
                             "finished; nothing was proposed") from exc
        raise
    _close_queued(world, pid)
    diff, files = diff or "", files or []
    review = _review(loop, reviewer, f"{title}\n\n{description}", diff)
    tests, tiers, tests_output = loop.tier_record()
    rounds, check = loop.record()
    proposal = {
        "id": pid, "repo": name, "title": title, "goal_id": goal_id, "branch": branch,
        "base": base, "head": head, "files": files, "diff": diff[:MAX_DIFF_CHARS],
        "diff_truncated": len(diff) > MAX_DIFF_CHARS, "diff_chars": len(diff),
        "tests": tests, "tiers": tiers, "tests_output": tests_output,
        "test_command": bool(repo.test_command), "repair_rounds": rounds,
        "isolation": "setup_failed" if loop.setup_failed else _isolation(on_host),
        "rounds": loop.rounds, "check": check, "stopped": loop.stopped,
        "review_cut_short": loop.review_cut_short,
        "review": review,
        "status": "decision" if waiting else "empty" if not changed else "pending",
        "approval_id": None, "created_at": time.time(), "merged_at": None,
        "owner": owner or None, "protected": loop.protected, "decision": waiting,
    }
    if changed:
        atomic_write_bytes(_proposal_dir(name) / f"{pid}.bundle",
                           vault._seal(loop.bundle, f"codebase/{name}/proposal-bundle/{pid}"))
    _save(proposal)  # the work is kept even if parking its approval fails
    if changed and not waiting:
        try:
            request_approval(world, proposal)
        except Exception as exc:  # noqa: BLE001 -- `maverick code renew` parks it again
            import logging
            if protected_refusal(proposal) is None:
                logging.getLogger(__name__).warning(
                    "proposal %s saved but its approval was not parked (%s); "
                    "run `maverick code renew %s`", pid, type(exc).__name__, pid)
    return proposal


def _exact_models(repo: vault.Repo, self_repo: bool):
    """No provider failover for a run whose change may turn out protected:
    the second checker's family check compares configured models, so the
    author and every normal checker must be answered by exactly theirs."""
    from contextlib import nullcontext

    from ..provider_failover import no_failover
    return no_failover() if self_repo or repo.protected_paths else nullcontext()


def _approval_expired(appr) -> bool:
    from ..approval_cards import ApprovalCardError, decode_approval_detail
    try:
        card = decode_approval_detail(appr.detail)
    except ApprovalCardError:
        return True
    return card is not None and time.time() >= float(card["expires_at"])


def request_approval(world, p: dict) -> int:
    """Park a (new) ``codebase_merge`` approval for a pending proposal: after
    propose, or when the earlier one expired (unanswered, or approved but never
    merged) or failed to park. Serialised per proposal, so two concurrent
    renewals cannot leave one approval that nothing reads."""
    caller = p
    with cross_process_lock(_proposal_dir(p["repo"]) / f"{p['id']}.renew", strict=True):
        try:
            p = {**p, **_load(p["repo"], p["id"])}  # the stored approval, not a stale copy
        except (OSError, ValueError, KeyError, VaultError):
            pass  # not saved yet (propose parks before its first read-back)
        if p["status"] == "decision":
            raise VaultError(DECISION_GAP)
        if p["status"] != "pending":
            raise VaultError(f"proposal {p['id']} is {p['status']}")
        refusal = protected_refusal(p)
        if refusal:
            raise VaultError(refusal)
        _check_current_protection(p)
        appr = world.get_approval(p["approval_id"]) if p.get("approval_id") else None
        if appr is not None and not (appr.status in ("pending", "approved")
                                     and _approval_expired(appr)):
            raise VaultError(f"proposal {p['id']} already has approval #{appr.id} ({appr.status})")
        from ..logging_config import reset_goal_context, set_goal_context
        context = set_goal_context(p.get("goal_id"))
        try:
            protected = bool(p.get("protected"))
            p["approval_id"] = world.create_approval(
                "codebase_merge", risk="high", scope=p["repo"],
                provenance=PROTECTED_PROVENANCE if protected else "codebase",
                approvals_required=PROTECTED_APPROVALS if protected else 1,
                # The person who started a protected change may not approve it.
                requested_by=(p.get("owner") if protected else None) or "agent:codebase",
                detail=_approval_detail(p))
        finally:
            reset_goal_context(context)
        _save(p)
        caller.update(p)
        return p["approval_id"]


APPROVAL_TTL = 7 * 24 * 3600.0  # the longest an operation card may stay open


def _safe_label(text: str, limit: int = 300) -> str:
    """A card label that cannot be refused: printable, never empty, and short
    enough to stay under the 500-character limit after secret redaction."""
    text = "".join(c if c.isprintable() else "?" for c in str(text)).strip()
    return (repr(text)[1:-1] if text else "(blank name)")[:limit]


def _approval_detail(p: dict) -> str:
    from ..approval_cards import ApprovalCardError
    try:
        return _approval_card(p, full=True)
    except ApprovalCardError:
        return _approval_card(p, full=False)  # names or title the card cannot state


_TESTS_GAP = "The repository's tests did not pass or are not configured."
QUICK_ONLY_LINE = ("The quick tests passed, but a quick pass alone never counts as the "
                   "tests passing.")
HOST_LINE = ("These steps ran on this computer without a container or separate processes, "
             "so they were not isolated from each other.")
HOST_GAP = "The steps were not isolated from each other on this computer."
# Only commands run in a step's work area get their own namespaces: a few
# tools (a language server, a patch fallback) start host processes directly.
NAMESPACE_LINE = ("Commands each step ran in its work area had their own processes and temporary "
                  "folder. They still shared this computer's other files, network and services, "
                  "unlike a container.")
NAMESPACE_GAP = ("The steps ran on this computer, not in a container, so they shared its files, "
                 "network and services.")
SETUP_FAILED_LINE = ("The isolated work area could not be set up for some steps, so their "
                     "commands did not run.")
_UNCHECKED_GAP = "Nobody independently tried to break this change."
NO_CONTAINER_REPRO_GAP = ("Lightwork did not re-run the checkers' commands, because the steps "
                          "do not run in a container.")
UNCONFIRMED_GAP = ("{n} blocker(s) passed their repro command after a repair, but no later "
                   "look confirmed the fix.")
SAME_FAMILY_GAP = ("Every checker used the same kind of model as the author, so they may "
                   "share its blind spots.")
PROTECTED_LINE = ("Protected: this change touches {n} protected path(s), so it needs a second "
                  "checker and two people to approve it.")
SELF_LINE = ("Protected: this change is to the repository Lightwork itself was installed from, so "
             "the whole repository counts as protected.")
TWO_PEOPLE = ("Two different people must approve this change, and neither may be the person "
              "who started it.")
PROTECTED_REFUSALS = {
    "unset": ("This change is protected, but no second checker is set. An administrator can "
              "choose one in Settings, then build the change again. It cannot be approved."),
    "same_family": ("This change is protected, but its second checker uses the same kind of model "
                    "as the author or a checker. It cannot be approved."),
    "uncompared": ("This change is protected, but Lightwork could not compare the second "
                   "checker's model with the others. It cannot be approved."),
}
NO_STARTER = ("This change is protected, but it was started without a signed-in person, such as "
              "from the command line. Someone else must approve it, so start it again from the "
              "Code page while signed in.")
BASE_MOVED = ("The project's main code no longer contains the version this change was built on. "
              "Build the change again.")
NEWLY_PROTECTED = ("Protected paths now cover this change, but it was not built as a protected "
                   "change. Build the change again so it gets a second checker and two approvers.")
NOT_LOOKED = ("This change is protected, but the second checker did not look at this version "
              "({reason}). It cannot be approved.")


def run_lines(p: dict) -> list[str]:
    """A change still being built, or stopped before it finished (Code page, Copilot)."""
    if p.get("status") == "running":
        return [STOPPED_LINE if _run_gone(p) else RUNNING_LINE]
    return [STOPPED_LINE] if p.get("status") == "stopped" else []


def protected_refusal(p: dict) -> str | None:
    """Why a protected proposal cannot be approved, in one plain sentence, or
    None (also for a proposal that is not protected, or saved before
    protected paths existed)."""
    rec = p.get("protected")
    if not isinstance(rec, dict):
        return None
    if not _named(p.get("owner")):
        return NO_STARTER
    if rec.get("problem"):
        return PROTECTED_REFUSALS.get(rec["problem"], PROTECTED_REFUSALS["uncompared"])
    if rec.get("state") != "ran" or rec.get("commit") != p.get("head"):
        return NOT_LOOKED.format(reason=rec.get("reason") or "it did not run")
    return None


def plain_refusal(exc: BaseException) -> str | None:
    """The sentence of a governance refusal a person can act on (shown as
    is by the dashboard), or None for any other error."""
    text = str(exc)
    plain = {TWO_PEOPLE, NEWLY_PROTECTED, SELF_REFUSAL, NO_STARTER, DECISION_GAP, BASE_MOVED,
             *PROTECTED_REFUSALS.values()}
    return text if text in plain or text.startswith(NOT_LOOKED.split("(")[0]) else None


def _named(principal: object) -> bool:
    """A person signed in with their own account (``user:<name>``)."""
    text = str(principal or "").strip()
    return text.startswith("user:") and len(text) > len("user:")


def protected_status(world, p: dict) -> str:
    """Whether a proposal is protected and what it still needs (Copilot):
    the approvals so far from people who count, and which second checker
    looked, or why it cannot be approved. Empty when it is not protected."""
    rec = p.get("protected")
    if not isinstance(rec, dict):
        return ""
    what = ("Protected, because it changes Lightwork's own code" if rec.get("self") else
            f"Protected, because it changes {rec.get('count', len(rec.get('paths') or []))} "
            "protected path(s)")
    refusal = protected_refusal(p)
    if refusal:
        return f"{what}. {refusal}"
    from ..safety.dual_control import person_key
    state = (world.approval_state(p["approval_id"]) or {}) if p.get("approval_id") else {}
    people = {person_key(a) for a in state.get("approvers") or () if _named(a)}
    people.discard(person_key(p.get("owner")))
    return (f"{what}. It needs two different people to approve, not the person who started "
            f"it: {min(len(people), PROTECTED_APPROVALS)} of {PROTECTED_APPROVALS} so far. "
            f"The second checker, {rec.get('model')}, looked at this version.")


def _protected_evidence(p: dict) -> tuple[list[str], list[str], list[str]]:
    """(the card's first lines, gaps, finding lines) for a protected change."""
    rec = p.get("protected")
    if not isinstance(rec, dict):
        return [], [], []
    paths = list(rec.get("paths") or [])
    lines = [SELF_LINE] if rec.get("self") else []
    if paths:
        lines.append(PROTECTED_LINE.format(n=rec.get("count", len(paths))))
        more = int(rec.get("count", len(paths))) - min(len(paths), 10)
        lines.append("Protected paths changed: " + ", ".join(_safe_label(x, 120) for x in paths[:10])
                     + (f", and {more} more." if more > 0 else "."))
    if _named(p.get("owner")):
        lines.append(TWO_PEOPLE)
    refusal = protected_refusal(p)
    findings = list(rec.get("findings") or [])
    gaps = [refusal] if refusal else []
    if refusal:
        lines.append(refusal)
    else:
        open_blockers = sum(1 for f in findings if f["severity"] == "blocker")
        lines.append(f"Second checker: {rec.get('model')}, a different kind of model, looked at this "
                     f"version. It reported {len(findings)} finding(s), {open_blockers} of them "
                     "blocking.")
        if open_blockers:
            gaps.append(f"{open_blockers} blocker(s) from the second checker are still open.")
    return lines, gaps, [_finding_line(f) for f in findings]


def _tiers_evidence(tiers: dict) -> tuple[list[str], list[str]]:
    """One line per test tier with its result on the version being approved.
    Only the full suite passing there reads as the tests passing."""
    def said(t: dict) -> str:
        if t["state"] == "not run":
            return f"not run ({t.get('reason')})"
        return t["state"] if t["state"] == "not configured" else \
            f"{t['state']} on the version you are approving (`{t.get('command')}`)"
    full = tiers.get("full") or {"state": "not configured"}
    if full["state"] in ("passed", "failed"):
        lines = [f"Tests: {full['state'].upper()}. Lightwork ran `{full.get('command')}` on the "
                 "exact version you are approving."]
    elif full.get("reason") == SETUP_REASON:
        lines = ["Tests: not run. The isolated work area could not be set up."]
    elif full["state"] == "not run":
        lines = [f"Tests: not run on the version you are approving ({full.get('reason')})."]
    else:
        lines = ["Tests: not configured. Lightwork has no full test command for this project."]
    gaps = [] if full["state"] == "passed" else [_TESTS_GAP]
    if full["state"] != "passed" and (tiers.get("quick") or {}).get("state") == "passed":
        lines.append(QUICK_ONLY_LINE)
    for tier, _, label in TIERS:
        t = tiers.get(tier) or {"state": "not configured"}
        if tier == "full":
            continue
        lines.append(f"{label}: {said(t)}.")
        if t["state"] == "failed":
            gaps.append(f"{label} failed on the version you are approving.")
        elif t["state"] == "not run" and tier != "quick":  # a quick tier never counts
            gaps.append(f"{label} did not run on the version you are approving "
                        f"({t.get('reason')}).")
    return lines, gaps


def tier_summary(p: dict) -> str:
    """Each test tier's result on the final version in one sentence (Copilot);
    empty for a proposal saved before tiers existed."""
    tiers = p.get("tiers")
    if not isinstance(tiers, dict):
        return ""
    parts = []
    for tier, _, label in TIERS:
        t = tiers.get(tier) or {"state": "not configured"}
        name = "all tests" if tier == "full" else label.lower()
        parts.append(f"{name} {t['state']}"
                     + (f" ({t.get('reason')})" if t["state"] == "not run" else ""))
    return "On the final version: " + "; ".join(parts) + "."


def _tests_evidence(p: dict) -> tuple[list[str], list[str]]:
    if isinstance(p.get("tiers"), dict):
        return _tiers_evidence(p["tiers"])
    tests = p.get("tests")
    if tests is None:
        return ["Tests: not configured. Nothing ran this project's tests."], [_TESTS_GAP]
    if tests.get("setup_failed"):
        return ["Tests: not run. The isolated work area could not be set up."], [_TESTS_GAP]
    verdict = "PASSED" if tests.get("passed") else "FAILED"
    gaps = [] if tests.get("passed") else [_TESTS_GAP]
    if "commit" not in tests:  # saved before tests ran on the pinned commit
        return [f"Tests: {verdict} (`{tests.get('command')}`)."], gaps
    if tests["commit"] != p["head"]:
        return ([f"Tests: {verdict} on an earlier version, not the one you are approving."],
                [_TESTS_GAP])
    return [f"Tests: {verdict}. Lightwork ran `{tests.get('command')}` on the exact version "
            "you are approving."], gaps


def _check_evidence(p: dict) -> tuple[list[str], list[str]]:
    check = p.get("check")
    if check is None:  # saved before the checker existed
        return ["Independent check: not run."], [_UNCHECKED_GAP]
    state, lines, gaps = check.get("state"), [], []
    if state == "off":
        when = "for this run" if check.get("off") == "run" else "in settings"
        return [f"Independent check: turned off {when}."], [_UNCHECKED_GAP]
    if state == "skipped" and check.get("cut_short"):
        return (["Independent check: was cut short by the spending limit, so nothing it found "
                 "was recorded."], [_UNCHECKED_GAP])
    if state == "skipped":
        return ["Independent check: did not run because the run stopped early."], [_UNCHECKED_GAP]
    if state == "failed":
        return ([f"Independent check: could not run ({check.get('error')})."],
                ["The independent check could not run, so this change was not checked."])
    findings = check.get("findings") or []
    still = sum(1 for f in findings if f["severity"] == "blocker" and f["status"] != "fixed")
    lines.append(f"Independent check: looked {check.get('runs')} time(s) and reported "
                 f"{len(findings)} finding(s); {still} blocker(s) still open.")
    if still:
        gaps.append(f"{still} blocker(s) from the independent check are still open.")
    unconfirmed = sum(1 for f in findings if f["severity"] == "blocker" and _repro_only_fixed(f))
    if unconfirmed:
        gaps.append(UNCONFIRMED_GAP.format(n=unconfirmed))
    if check.get("repros_skipped"):
        gaps.append(NO_CONTAINER_REPRO_GAP)
    if check.get("commit") != p["head"]:
        lines.append("Not every checker finished looking at the version you are approving."
                     if len(check.get("checkers") or ()) > 1 else
                     "The last check looked at an earlier version, not the one you are approving.")
        gaps.append("The independent check did not look at the version you are approving.")
    if check.get("error") and len(check.get("checkers") or ()) <= 1:
        lines.append(f"A check could not run ({check['error']}).")
    if check.get("cut_short"):
        lines.append("A later look was cut short by the spending limit.")
    who, family = _checker_lines(check)
    return lines + who + _repro_lines(findings), gaps + family


def _checker_lines(check: dict) -> tuple[list[str], list[str]]:
    """Each checker's model and whether it shares the author's provider family;
    a gap when every one of them does."""
    every = [c for c in check.get("checkers") or () if isinstance(c, dict)]
    lines = [f"The checks ran in the container image {check['image']}."] \
        if check.get("image") else []
    if len(every) > 1:  # each checker's own error, whether or not it looked before
        lines += [f"Checker {c.get('n')} could not run ({c['error']})." for c in every
                  if c.get("error")]
    rows = [c for c in every if c.get("commit")]  # only checkers that looked
    for c in rows:
        if not c.get("model"):
            if len(every) > 1:
                lines.append(f"Checker {c.get('n')}: its model was not recorded.")
            continue
        kind = {True: "the same kind of model as the author",
                False: "a different kind of model from the author"}.get(
            c.get("same_family"), "a model that could not be compared with the author's")
        lines.append(f"Checker {c.get('n')} used {c['model']}, {kind}.")
    same = bool(rows) and all(c.get("same_family") is True for c in rows)
    return lines, [SAME_FAMILY_GAP] if same else []


def _repro_lines(findings: list[dict]) -> list[str]:
    states = [f.get("repro_state") for f in findings if f.get("repro_state")]
    if not states:
        return []
    confirmed, missed = states.count("confirmed"), states.count("not reproduced")
    not_run, skipped = states.count("not run"), states.count("not re-run")
    return [f"Lightwork re-ran {confirmed + missed} finding(s) on its own copy of the change: "
            f"{confirmed} confirmed, {missed} not reproduced."
            + (f" {not_run} could not be run." if not_run else "")
            + (f" {skipped} more were not re-run." if skipped else "")]


def _finding_line(f: dict, many: bool = False) -> str:
    """One finding in plain words: who found it, how sure, and who says it is fixed."""
    state = f.get("repro_state")
    how = ("shown by running a command, in the checker's own words" if f.get("evidence") == "ran"
           else "from reading the code")
    if state == "confirmed":
        how = "confirmed: Lightwork re-ran it and it failed"
    elif state == "not reproduced":
        how = f"not reproduced when Lightwork re-ran it: {f.get('repro_reason')}; read only"
    elif state in ("not re-run", "not run"):
        how += f"; {state}: {f.get('repro_reason')}"
    status = f["status"]
    if status == "fixed" and f.get("fixed_by") == "lightwork":
        status += (": its repro command passed on the repaired version (the author saw the "
                   "command); " + ("a later look confirmed it" if f.get("checker_confirmed")
                                   else "no later look confirmed it"))
    elif status == "fixed" and f.get("fixed_by"):
        status += ": the checker's word"
    elif f.get("checker_confirmed") is False:
        status += (" (its repro command passed on the repaired version, but the checker "
                   "says it is still wrong)")
    elif status != "fixed" and (f.get("recheck") or {}).get("result") not in (None, "failed"):
        status += (" (Lightwork could not re-run it on the last version: "
                   f"{f['recheck'].get('reason')})")
    who = " from the second checker" if f.get("checker") == "protected" else \
        f" from checker {f.get('checker', 1)}" if many else ""
    return f"Finding {f['id']}{who}, {f['severity']}, {status}: {f['what']} ({how})."


def evidence(p: dict) -> dict:
    """What was and was not checked, in plain words: the one source for the
    approval card, the CLI, the dashboard and Copilot. A protected change's
    lines come first (``protected``): what is protected, who must approve,
    and the second checker's result or why it cannot be approved. ``gaps`` lists every
    reason the change is not fully checked; it is empty only when the tests
    passed on the approved commit and the checker looked at that commit and
    left no blocker open. Proposals saved before repair rounds and the checker
    existed read as not checked. ``tests`` is the test lines alone (one per
    tier), for answers too short for every line."""
    lines, gaps = _tests_evidence(p)
    tests = list(lines)
    isolation = p.get("isolation")
    if isolation in ("host", "namespace"):
        lines.append(HOST_LINE if isolation == "host" else NAMESPACE_LINE)
        gaps.append(HOST_GAP if isolation == "host" else NAMESPACE_GAP)
    elif isolation == "setup_failed":
        lines.append(SETUP_FAILED_LINE)
        gaps.append(SETUP_FAILED_LINE)
    rounds = p.get("repair_rounds")
    if isinstance(rounds, dict):
        lines.append(f"Repair rounds: {rounds.get('used', 0)} of {rounds.get('allowed', 0)} used.")
    stopped = p.get("stopped")
    if stopped == "budget":
        lines.append("Stopped early: the spending limit ran out, so later rounds did not run.")
        gaps.append("The spending limit ran out before every round could run.")
    elif stopped == "decision":
        gaps.append(DECISION_GAP)
    elif stopped:
        lines.append("Stopped early: a repair round failed, so the last tested version is shown.")
        gaps.append("A repair round failed before every round could run.")
    if p.get("review_cut_short"):
        gaps.append("The spending limit ran out before the diff review finished.")
    check_lines, check_gaps = _check_evidence(p)
    check = p.get("check") or {}
    many = len(check.get("checkers") or ()) > 1
    first, protected_gaps, protected_findings = _protected_evidence(p)
    first = run_lines(p) + decision_lines(p) + first
    return {"lines": first + lines + check_lines, "gaps": protected_gaps + gaps + check_gaps,
            "tests": tests, "protected": first,
            "findings": [_finding_line(f, many) for f in check.get("findings") or []]
            + protected_findings}


def decision_lines(p: dict) -> list[str]:
    """What a code change that stopped for a person's decision waits for, and
    what the person does next."""
    return [f"Waiting for a person's decision: “{_safe_label(d.get('question'), 300)}”. "
            "Answer it on the Approvals page or with maverick decisions answer "
            f"{d.get('id')}, then start a new code change." if d.get("open", True) else
            f"A person was asked to decide “{_safe_label(d.get('question'), 300)}” before "
            "this step could finish. Start a new code change to use the answer."
            for d in p.get("decision") or ()]


def _approval_card(p: dict, *, full: bool) -> str:
    """A structured approval card (the only kind the dashboard lets a human
    approve) committing to the repository, branch, base and approved head,
    and stating plainly what was and was not checked."""
    from ..approval_cards import encode_operation_approval_detail
    review = p["review"]
    facts = evidence(p)
    first = facts["protected"]
    lines = [*first, f"Branch {p['branch']} at {p['head'][:12]} from "
             f"{p['base'][:12]}; {len(p['files'])} file(s) changed.", *facts["lines"][len(first):]]
    # Counts and statuses only: this card reaches chat channels and lists that
    # need only operate access, and finding text can quote vaulted code.
    findings = (p.get("check") or {}).get("findings") or []
    if findings:
        counts: dict[str, int] = {}
        for f in findings:
            key = f"{f['severity']} {f['status']}"
            counts[key] = counts.get(key, 0) + 1
        confirmed = sum(1 for f in findings if f.get("repro_state") == "confirmed")
        lines.append("Independent check findings: "
                     + ", ".join(f"{n} {key}" for key, n in counts.items())
                     + (f"; {confirmed} confirmed by Lightwork re-running them" if confirmed
                        else "")
                     + f". Read them with maverick code show {p['id']} or on the Code page.")
    lines.append("Independent review: " + (
        "cut short by the spending limit." if review is None and p.get("review_cut_short") else
        "not run" if review is None else
        ("approves" if review.get("approves") else "objects")
        + f" ({review.get('blockers', 0)} blocker(s))"))
    if p.get("diff_truncated"):
        lines.append(f"WARNING: the diff is {p['diff_chars']} characters; review and the stored "
                     f"copy cover only the first {MAX_DIFF_CHARS}. Inspect the branch in full "
                     "before approving.")
    lines += [f"  {_safe_label(f)}" for f in p["files"][:40]] if full else []
    if len(p["files"]) > 40:
        lines.append(f"  ... and {len(p['files']) - 40} more file(s)")
    lines.append(f"Inspect: maverick code show {p['id']}")
    lines = [_safe_label(line) for line in lines][:24]
    return encode_operation_approval_detail(
        action="codebase_merge",
        summary=_safe_label(f"Merge Lightwork proposal {p['id']} into {p['repo']}"
                            + (f": {p['title']}" if full else "")),
        target_label=f"{p['repo']} <- {p['branch']}"[:500],
        target={"repo": p["repo"], "branch": p["branch"]},
        parameters={"proposal": p["id"], "base": p["base"], "head": p["head"],
                    "files": p["files"]},
        parameter_summary=lines, actor="agent:codebase", role="feature_swarm",
        known_effects=[f"Merges the proposal into {p['repo']}'s default branch in the vault "
                       "(no-fast-forward); pushing upstream is a separate step."[:500]],
        unresolved_assumptions=[_safe_label(g) for g in facts["gaps"]][:24],
        before=f"{p['repo']} default branch at {p['base'][:12]}.",
        after=f"{p['repo']} default branch includes {p['head'][:12]}.",
        irreversible=False, ttl_seconds=APPROVAL_TTL)


def status(world, p: dict) -> str:
    if p["status"] == "running":
        return "stopped" if _run_gone(p) else "running"
    if p["status"] in ("merged", "empty", "conflict", "decision", "stopped"):
        return p["status"]
    appr = world.get_approval(p["approval_id"]) if p["approval_id"] else None
    if appr is None:
        if protected_refusal(p):
            return "blocked"  # a protected change that cannot be approved as it is
        return "unrequested"  # its approval failed to park: `maverick code renew`
    if appr.status in ("pending", "approved") and _approval_expired(appr):
        return "expired"      # past its card's expiry: `maverick code renew`
    return {"approved": "approved", "denied": "rejected"}.get(appr.status, "pending")


def _require_approved(world, p: dict) -> None:
    """The approval itself must be an approved codebase_merge for this repository
    -- not merely the proposal's recorded state."""
    appr = world.get_approval(p["approval_id"]) if p["approval_id"] else None
    if (appr is None or appr.status != "approved" or appr.action != "codebase_merge"
            or appr.scope != p["repo"]):
        raise VaultError(f"proposal {p['id']} is {status(world, p)}; "
                         "a human must approve it first")
    if _approval_expired(appr):
        # Like every other approved operation: an approval past its card's
        # expiry no longer authorizes the change it described.
        raise VaultError(f"proposal {p['id']}'s approval #{appr.id} has expired; "
                         f"run `maverick code renew {p['id']}` and approve it again")
    if p.get("protected"):
        problem = protected_refusal(p) or _protected_approval_problem(world, p, appr)
        if problem:
            raise VaultError(problem)


def _require_current_protection(p: dict, host: Path) -> None:
    """Protection again, from the project's CURRENT protected paths and
    whether it is now the running installation's own repository, against
    both base..head and merge-base(current tip, head)..head (both sides of a
    rename): a change that was not built as a protected one, but is one now,
    never merges, pushes or asks for approval on the strength of its
    single-approver checks. A change whose base is no longer in the main
    code is refused outright."""
    repo = vault.get(p["repo"])
    tip = _git(["rev-parse", "--verify", f"refs/heads/{repo.default_branch}"],
               git_dir=host).strip()
    if not vault._is_ancestor(host, p["base"], tip):
        # A merge would bring in commits that nothing checked or approved.
        raise VaultError(BASE_MOVED)
    self_repo = is_installation(repo, host)
    if self_repo and not loop_settings()["allow_self_changes"]:
        raise VaultError(SELF_REFUSAL)
    if p.get("protected"):
        return
    # What the merge brings in (from the merge base with the current tip),
    # and the change as it was built (from its base).
    since = {p["base"], _git(["merge-base", tip, p["head"]], git_dir=host).strip()}
    paths = {f for start in since for f in _git(
        ["diff", "--name-only", "--no-renames", "-z", start, p["head"]],
        git_dir=host).split("\0") if f}
    if self_repo or vault.protected_matches(repo.protected_paths, sorted(paths)):
        raise VaultError(NEWLY_PROTECTED)


def _check_current_protection(p: dict) -> None:
    """:func:`_require_current_protection` on a fresh host copy (renew)."""
    if not (_proposal_dir(p["repo"]) / f"{p['id']}.bundle").exists():
        return  # nothing to merge or push without its branch bundle
    with vault.host_repo(p["repo"]) as host:
        _fetch_proposal(p, host)
        _require_current_protection(p, host)


def _protected_approval_problem(world, p: dict, appr) -> str | None:
    """A protected change merges or pushes only on the votes of two distinct
    named people, neither the person who started it, whatever surface they
    voted on."""
    from ..safety.dual_control import person_key
    state = world.approval_state(appr.id) or {}
    people = {person_key(a) for a in state.get("approvers") or () if _named(a)}
    people.discard(person_key(p.get("owner")))
    if (appr.provenance != PROTECTED_PROVENANCE
            or int(appr.approvals_required or 1) < PROTECTED_APPROVALS
            or len(people) < PROTECTED_APPROVALS):
        return TWO_PEOPLE
    return None


def _fetch_proposal(p: dict, host: Path) -> None:
    """Load the proposal's branch into ``host`` and prove it is the approved commit."""
    raw = (_proposal_dir(p["repo"]) / f"{p['id']}.bundle").read_bytes()
    with tempfile.TemporaryDirectory(prefix="lw-prop-") as tmp:
        b = Path(tmp) / "p.bundle"
        b.write_bytes(vault._unseal(raw, f"codebase/{p['repo']}/proposal-bundle/{p['id']}"))
        try:
            _git(["fetch", "-q", str(b), f"+refs/heads/{p['branch']}:refs/heads/{p['branch']}"],
                 git_dir=host)
        except VaultError as exc:
            if "prerequisite" in str(exc):  # its base is no longer in the vault at all
                raise VaultError(BASE_MOVED) from exc
            raise
    tip = _git(["rev-parse", "--verify", f"refs/heads/{p['branch']}"], git_dir=host).strip()
    if tip != p["head"]:
        raise VaultError(f"proposal {p['id']} branch is not the approved commit; refused")


def merge(world, pid: str) -> dict:
    """Merge an APPROVED proposal into the vault's default branch (no fast-forward,
    so the merge is one reviewable commit). A conflict leaves the vault as it was."""
    p = find(pid)
    _require_approved(world, p)
    if p["status"] == "merged":
        raise VaultError(f"proposal {pid} is already merged")
    repo = vault.get(p["repo"])
    with cross_process_lock(vault._bundle_path(p["repo"]), strict=True), \
            vault.host_repo(p["repo"]) as host:
        _fetch_proposal(p, host)
        _require_current_protection(p, host)
        work = vault.clone_work(host, host.parent / "merge-work", repo.default_branch)
        _git(["fetch", "-q", str(host), f"refs/heads/{p['branch']}:refs/heads/{p['branch']}"],
             cwd=work)
        try:
            _git(["merge", "-q", "--no-ff", p["branch"], "-m",
                  f"Merge Lightwork proposal {pid}: {p['title']}"], cwd=work, env=_IDENTITY)
        except VaultError:
            p["status"] = "conflict"
            _save(p)
            raise VaultError(f"proposal {pid} no longer merges cleanly; request it again") from None
        _git(["fetch", "-q", str(work),
              f"+refs/heads/{repo.default_branch}:refs/heads/{repo.default_branch}"],
             git_dir=host)
        vault.commit_back(p["repo"], host)
    p.update(status="merged", merged_at=time.time())
    _save(p)
    return p


def settle(world) -> list[dict]:
    """Merge every proposal a human has approved since the last settle; report
    the outcome of each (merged, or the reason it did not merge)."""
    out = []
    for p in list_proposals():
        if p["status"] == "pending" and status(world, p) == "approved":
            try:
                merge(world, p["id"])
                out.append({"id": p["id"], "repo": p["repo"], "outcome": "merged"})
            except Exception as exc:  # noqa: BLE001 -- one bad proposal never stops the rest
                out.append({"id": p["id"], "repo": p["repo"],
                            "outcome": str(exc) if isinstance(exc, VaultError)
                            else f"error: {type(exc).__name__}"})
    return out


def push(world, pid: str) -> str:
    """Push an APPROVED proposal's branch (the approved commit, verified) to the
    repository's source remote, for a pull request there. Returns the branch."""
    p = find(pid)
    _require_approved(world, p)
    repo = vault.get(p["repo"])
    with vault.host_repo(p["repo"]) as host:
        _fetch_proposal(p, host)
        _require_current_protection(p, host)
        _git(["push", "-q", repo.source, f"refs/heads/{p['branch']}:refs/heads/{p['branch']}"],
             git_dir=host, token_env=repo.token_env)
    return p["branch"]


def default_runner(*, max_dollars: float | None = None, user_id: str | None = None,
                   allowed_suites: frozenset[str] | None = None, budget=None) -> Runner:
    """Run the goal as a normal governed swarm whose sandbox is the working copy.
    Pass the feature run's ``budget`` so every round charges the same cap;
    without one, each call builds its own from configuration."""
    def run(goal_id: int, work: Path) -> object:
        from ..llm import LLM
        from ..orchestrator import run_goal_sync
        from ..sandbox import build_sandbox
        from ..world_model import close_world_if_owned, open_world
        world = open_world()
        try:
            return run_goal_sync(LLM(), world,
                                 budget if budget is not None else feature_budget(max_dollars),
                                 goal_id, sandbox=build_sandbox(workdir=str(work)),
                                 user_id=user_id, allowed_suites=allowed_suites)
        finally:
            close_world_if_owned(world)
    return run


def checker_model() -> str:
    """The checker's model: the ``reviewer`` role (``[models] reviewer``), so
    it can differ from the author's; swapped for the configured cross-family
    model when the two share a provider family (as the diff reviewer does)."""
    from ..llm import model_for_role
    from ..verifier import _cross_family_fallback, _same_family
    model = model_for_role("reviewer")
    if _same_family(model, model_for_role("orchestrator")):
        model = _cross_family_fallback(model) or model
    return model


# The configured work area -> the backend that runs the checker image with at
# least its isolation. Any other work area (firecracker, kubernetes, ssh, ...)
# cannot carry an image this way, so the check could not run.
_IMAGE_BACKENDS = {"local": "docker", "docker": "docker", "gvisor": "gvisor",
                   "podman": "podman"}
# The checker image's own ordinary user (deploy/checker/Dockerfile ``USER``).
IMAGE_USER = "1000:1000"


def _host_is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _give_to_image_user(path: Path) -> None:
    """Hand a throwaway copy to the image's ordinary user (root hosts only).
    Links are changed themselves, never followed. The copy's parent folder
    stays private to root, so no host account can reach it."""
    uid, gid = (int(x) for x in IMAGE_USER.split(":"))
    os.lchown(path, uid, gid)
    for folder, dirs, files in os.walk(path):
        for name in dirs + files:
            os.lchown(os.path.join(folder, name), uid, gid)


def image_sandbox(image: str, workdir: str):
    """The container backend running ``image``, with the rest of ``[sandbox]``
    (network, memory, user, gVisor's runtime): Docker for the local and docker
    work areas, gVisor's runsc for gvisor, Podman for podman. It never pulls:
    a missing image fails instead of being fetched. On a root host it runs as
    the image's ordinary user. Raises when the configured work area cannot
    carry an image or the backend cannot be built; callers report that and
    never run the command on this computer instead."""
    from ..config import get_sandbox, load_config
    from ..sandbox import build_sandbox
    configured = str(get_sandbox().get("backend") or "local").strip().lower()
    chosen = _IMAGE_BACKENDS.get(configured)
    if chosen is None:
        raise RuntimeError(f"the configured work area ({_safe_label(configured, 40)}) cannot "
                           "run a container image, and the check never uses a weaker one")
    cfg = load_config().get("sandbox")
    cfg = dict(cfg) if isinstance(cfg, dict) else {}
    box = build_sandbox(workdir=workdir, backend=chosen, sandbox_config={
        **cfg, "backend": chosen, "image": image, "cross_run_pool": False,
        "reuse_container": False})
    box.pull = "never"
    if _host_is_root():
        box.run_as = IMAGE_USER
    return box


def checker_sandbox(workdir: str):
    """A checker's sandbox: the ``[codebase] checker_image`` container when one
    is set, else the configured backend."""
    image = loop_settings()["checker_image"]
    if image:
        return image_sandbox(image, workdir)
    from ..sandbox import build_sandbox
    return build_sandbox(workdir=workdir)


def default_checker(*, budget, user_id: str | None = None,
                    allowed_suites: frozenset[str] | None = None,
                    model: str | None = None, exact_model: bool = False) -> Checker:
    """The independent checker: a separate governed run with a fresh context,
    whose sandbox is its own throwaway copy of the pinned commit, charged to
    the feature run's ``budget``. Its run is a fresh context
    (:func:`maverick.tools.fresh_context_run`): no tool that reads past goals
    or shared memory, and no prior goals recalled into its brief. ``model``
    defaults to :func:`checker_model`; the checker carries it as ``.model``.
    With ``exact_model`` no provider failover applies: when that model
    cannot answer, the check does not happen."""
    chosen = model or checker_model()

    def check(goal_id: int, copy: Path) -> object:
        from .. import orchestrator
        from ..llm import LLM
        from ..tools import fresh_context_run
        from ..world_model import close_world_if_owned, open_world
        world = open_world()
        box = checker_sandbox(str(copy))
        from contextlib import nullcontext

        from ..provider_failover import no_failover
        try:
            with fresh_context_run(), (no_failover() if exact_model else nullcontext()):
                return orchestrator.run_goal_sync(LLM(), world, budget, goal_id, sandbox=box,
                                                  user_id=user_id,
                                                  allowed_suites=allowed_suites,
                                                  orchestrator_model_override=chosen)
        finally:
            _close(box)
            close_world_if_owned(world)
    check.model = chosen  # type: ignore[attr-defined]
    return check


def default_checkers(*, budget, user_id: str | None = None,
                     allowed_suites: frozenset[str] | None = None) -> list[Checker]:
    """``[codebase] checkers`` independent checkers, one model each from
    ``[codebase] checker_models`` (the :func:`checker_model` rule where the
    list is empty or short). Each extra checker is one more agent run per look."""
    settings = loop_settings()
    models = list(settings["checker_models"])
    return [default_checker(budget=budget, user_id=user_id, allowed_suites=allowed_suites,
                            **({"model": models[i]} if i < len(models) else {}))
            for i in range(max(1, int(settings["checkers"])))]


def default_protected_checker(*, budget, user_id: str | None = None,
                              allowed_suites: frozenset[str] | None = None) -> Checker | None:
    """The second checker a change to a protected path needs: ``[codebase]
    protected_checker_model``, charged to the feature run's ``budget``; None
    when it is unset (a protected change then cannot be approved)."""
    model = loop_settings()["protected_checker_model"]
    if not model:
        return None
    return default_checker(budget=budget, user_id=user_id, allowed_suites=allowed_suites,
                           model=model, exact_model=True)


def default_reviewer(*, budget=None) -> Reviewer:
    """The independent diff reviewer (cross-family where possible), charged
    to the feature run's ``budget``."""
    def review(brief: str, diff: str) -> dict:
        import asyncio

        from ..llm import LLM
        from ..reviewer import review_diff
        verdict = asyncio.run(review_diff(brief, diff, LLM(), budget))
        return {"approves": bool(verdict.approves), "confidence": float(verdict.confidence),
                "blockers": len(verdict.blockers),
                "comments": [{"path": c.path, "line": c.line, "severity": c.severity,
                              "message": c.message} for c in verdict.comments[:50]]}
    return review


__all__ = ["checker_sandbox", "default_checker", "default_checkers", "default_protected_checker",
           "default_reviewer", "default_runner", "evidence", "feature_budget", "find",
           "list_proposals", "loop_settings", "merge", "propose", "protected_refusal",
           "protected_status", "push",
           "run_tests", "settle", "status", "tier_summary"]


def _check_word(check: dict, head: str) -> str:
    """One word for the checker's outcome: off | not_run | failed | open | clean."""
    state = check.get("state")
    if state in ("off", "failed"):
        return state
    if state != "ran" or check.get("commit") != head:
        return "not_run"
    still = any(f["severity"] == "blocker" and (f["status"] != "fixed" or _repro_only_fixed(f))
                for f in check.get("findings") or ())
    return "open" if still else "clean"


def summary(world) -> dict:
    """Read-only projection for the dashboard: repositories and proposals, never
    code, diffs or test output."""
    repos = [{"name": r.name, "default_branch": r.default_branch, "head": r.head[:12],
              "protect": r.protect, "tests": bool(r.test_command),
              "test_tiers": [tier for tier, key, _ in TIERS if getattr(r, key)],
              "protected_paths": len(r.protected_paths), "updated_at": r.updated_at}
             for r in vault.list_repos()]
    proposals = []
    for p in list_proposals()[:200]:
        tests = p.get("tests")
        review = p.get("review")
        check = p.get("check")
        proposals.append({
            "id": p["id"], "repo": p["repo"], "title": p["title"], "branch": p["branch"],
            "status": status(world, p), "files": len(p["files"]),
            "tests": None if tests is None else tests["passed"],
            # False when the full suite did not run on the final commit.
            "tests_ran": None if tests is None else tests.get("ran", True),
            "review": None if review is None else bool(review.get("approves")),
            "check": None if check is None else _check_word(check, p["head"]),
            "gaps": len(evidence(p)["gaps"]), "protected": bool(p.get("protected")),
            "approval_id": p["approval_id"], "created_at": p["created_at"]})
    return {"schema": "lightwork.codebase-summary.v1", "enabled": vault.enabled(),
            "repos": repos, "proposals": proposals}
